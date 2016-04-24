package main

import (
	"fmt"
	"os"
	"encoding/json"
	"time"
	log "github.com/Sirupsen/logrus"
	"sync"
	"strings"
	"path"
	"crypto/rand"
	"crypto/tls"
	"math/big"

	"github.com/bwalex/go-cgroups"
	"github.com/docker/libkv"
	"github.com/docker/libkv/store"
	"github.com/docker/libkv/store/consul"
	"github.com/docker/libkv/store/etcd"
	"github.com/docker/libkv/store/zookeeper"
	"github.com/spf13/cobra"
	"github.com/influxdata/influxdb/client/v2"
)

var hostname, _ = os.Hostname()

var globalFlags = struct {
	CgroupRoot         string

	StoreType          string
	StoreURI           string
	StoreBase          string
	StoreUser          string
	StorePassword      string
	StoreTLSNoVerify   bool
	StoreUseTLS        bool

	InfluxURI          string
	InfluxDatabase     string
	InfluxUser         string
	InfluxPassword     string
	InfluxTLSNoVerify  bool
}{
	CgroupRoot:        cgroups.DefaultSysfsRoot,

	StoreType:         "etcd",
	StoreURI:          "localhost:2379",
	StoreBase:         "cgroups-influx/" + hostname,
	StoreUser:         "",
	StorePassword:     "",
	StoreTLSNoVerify:  false,
	StoreUseTLS:       false,

	InfluxURI:         "http://localhost:8086",
	InfluxDatabase:    "cgroups",
	InfluxUser:        "",
	InfluxPassword:    "",
	InfluxTLSNoVerify: false,
}

// InfluxDB client settings
//  - http/https (scheme)
//  - verify TLS certificate?
//  - URI
//  - username
//  - password
//  - database
//
// Global settings
//  - global metadata
//  - default sampling interval
//  - cgroup root
//  - jitter
//
// Per collector settings
//  - metadata
//  - cgroup

// Collection:
//   sync waitgroups

type GlobalConfig struct {
	CgroupRoot    string            `json:"cgroup_root"`
	Tags          map[string]string `json:"tags"`
	IntervalSecs  int               `json:"interval_secs"`
	JitterSecs    int               `json:"jitter_secs"`
}

type CgroupConfig struct {
	Cgroup        string            `json:"cgroup"`
	Tags          map[string]string `json:"tags"`
}

var ctx struct {
	sync.Mutex
	cgs          []CgroupConfig
	config       GlobalConfig
	wg           sync.WaitGroup
	changeChan   chan interface{}
	influxClient client.Client
}

func ensureExists(kv store.Store, key string, dir bool) error {
	exists, err := kv.Exists(key)
	if err != nil {
		return err
	} else if !exists {
		err := kv.Put(key, []byte(""), &store.WriteOptions{IsDir: dir})
		return err
	}

	return nil
}

func updateConfig(pair *store.KVPair) error {
	var config GlobalConfig
	err := json.Unmarshal(pair.Value, &config)
	if err != nil {
		log.Printf("Error decoding config JSON: %s", err)
		return err
	}
	fmt.Printf("Applying new configuration: %+v\n", config)
	ctx.Lock()
	ctx.config = config
	ctx.Unlock()

	ctx.changeChan <- nil

	return nil
}

func updateCgroups(pairs []*store.KVPair) error {
	cgs := make([]CgroupConfig, 0, len(pairs))
	for i := range pairs {
		var cg CgroupConfig
		err := json.Unmarshal(pairs[i].Value, &cg)
		if err != nil {
			log.Printf("Error decoding cgroup JSON at key %s: %s", pairs[i].Key, err)
			return err
		}
		cgs = append(cgs, cg)
	}
	fmt.Printf("New cgroups: %+v\n", cgs)
	ctx.Lock()
	ctx.cgs = cgs
	ctx.Unlock()

	return nil
}

func ConfigWatcher() {
	var tlsConf *tls.Config

	if globalFlags.StoreUseTLS {
		tlsConf = &tls.Config{
			InsecureSkipVerify: globalFlags.StoreTLSNoVerify,
		}
	}
	// Initialize a new store with consul
	kv, err := libkv.NewStore(
		store.Backend(globalFlags.StoreType),
		[]string{globalFlags.StoreURI},
		&store.Config{
			ConnectionTimeout: 10*time.Second,
			Username: globalFlags.StoreUser,
			Password: globalFlags.StorePassword,
			TLS: tlsConf,
		},
	)
	if err != nil {
		log.Fatal("Cannot create store")
	}

	err = ensureExists(kv, globalFlags.StoreBase, true)
	if err != nil {
		log.Fatalf("Bla: %s", err)
	}

	err = ensureExists(kv, path.Join(globalFlags.StoreBase, "cgroups"), true)
	if err != nil {
		log.Fatalf("Bla: %s", err)
	}

	err = ensureExists(kv, path.Join(globalFlags.StoreBase, "config"), false)
	if err != nil {
		log.Fatalf("Bla: %s", err)
	}

	stopCh := make(<-chan struct{})
	configEvents, err := kv.Watch(path.Join(globalFlags.StoreBase, "config"), stopCh)
	cgroupEvents, err := kv.WatchTree(path.Join(globalFlags.StoreBase, "cgroups"), stopCh)

	ev_loop: for {
		select {
		case pair := <-configEvents:
			if pair == nil {
				break ev_loop
			}
			updateConfig(pair)

		case pairs := <-cgroupEvents:
			if pairs == nil {
				break
			}
			updateCgroups(pairs)
		}
	}

	ctx.wg.Done()
}


func init() {
	ctx.cgs = make([]CgroupConfig, 0)
	ctx.changeChan = make(chan interface{})
}


type MeasurementBatch interface {
	AddPoint(measurement string, tags map[string]string, fields map[string]interface{}, time time.Time)
}

type MeasurementBatchInflux struct {
	points []*client.Point
	sync.Mutex
}

func (batch *MeasurementBatchInflux) AddPoint(measurement string, tags map[string]string, fields map[string]interface{}, time time.Time) {
	point, err := client.NewPoint(measurement, tags, fields, time)
	if err == nil {
		batch.Lock()
		batch.points = append(batch.points, point)
		batch.Unlock()
	}
}

type CpuHistory struct {
	stats      cgroups.CpuStat
	sampleTime time.Time
}

type NetHistory struct {
	stats      cgroups.NetStat
	sampleTime time.Time
}

type BlkioHistory struct {
	stats      cgroups.BlkioStat
	sampleTime time.Time
}

var cpuHist = make(map[string]CpuHistory)
var cpuHistMtx sync.RWMutex
var netHist = make(map[string]NetHistory)
var netHistMtx sync.RWMutex
var blkioHist = make(map[string]BlkioHistory)
var blkioHistMtx sync.RWMutex


func collectCpu(cg CgroupConfig, tags map[string]string, batch MeasurementBatch) {
	stats, err := cgroups.GetCpuStats(cgroups.Cgroup{
		Root:   ctx.config.CgroupRoot,
		Cgroup: cg.Cgroup,
	})

	if err == nil {
		var deltaStats cgroups.CpuDeltaStat

		totalCpuTimeUs := stats.UserTimeUs + stats.SystemTimeUs

		cpuHistMtx.RLock()
		if hist, ok := cpuHist[cg.Cgroup]; ok {
			deltaStats = stats.Delta(hist.stats)
		}
		cpuHistMtx.RUnlock()

		log.Printf("stats: %+v\n", stats)
		log.Printf("deltaStats: %+v\n", deltaStats)

		batch.AddPoint("cpu", tags, map[string]interface{}{
			"time_us":           int64(totalCpuTimeUs),
			"user_time_us":      int64(stats.UserTimeUs),
			"sys_time_us":       int64(stats.SystemTimeUs),
			"throttled_time_us": int64(stats.ThrottledTimeUs),
			"throttled_pct":     stats.ThrottledPct,
			"usage_pct":         deltaStats.UsagePct,
			"user_usage_pct":    deltaStats.UserUsagePct,
			"sys_usage_pct":     deltaStats.SystemUsagePct,
		}, stats.SampleTime)

		cpuHistMtx.Lock()
		cpuHist[cg.Cgroup] = CpuHistory{
			stats:      stats,
			sampleTime: stats.SampleTime,
		}
		cpuHistMtx.Unlock()
	} else {
		log.Printf("Error on cgroup sampling: %s\n", err)
	}
}

func collectNet(cg CgroupConfig, tags map[string]string, batch MeasurementBatch) {
	stats, err := cgroups.GetNetStats(cgroups.Cgroup{
		Root:   ctx.config.CgroupRoot,
		Cgroup: cg.Cgroup,
	}, "")

	if err == nil {
		var deltaStats cgroups.NetDeltaStat

		netHistMtx.RLock()
		if hist, ok := netHist[cg.Cgroup]; ok {
			deltaStats = stats.Delta(hist.stats)
		}
		netHistMtx.RUnlock()

		log.Printf("stats: %+v\n", stats)
		log.Printf("deltaStats: %+v\n", deltaStats)

		batch.AddPoint("net", tags, map[string]interface{}{
			"rx_bytes":          int64(stats.RxBytes),
			"rx_packets":        int64(stats.RxPackets),
			"rx_errors":         int64(stats.RxErrors),
			"rx_drop":           int64(stats.RxDrop),
			"rx_byte_rate":      int64(deltaStats.RxByteRate),
			"rx_packet_rate":    int64(deltaStats.RxPacketRate),
			"rx_drop_rate":      float64(deltaStats.RxDropRate),
			"rx_error_rate":     float64(deltaStats.RxErrorRate),
			"tx_bytes":          int64(stats.TxBytes),
			"tx_packets":        int64(stats.TxPackets),
			"tx_errors":         int64(stats.TxErrors),
			"tx_drop":           int64(stats.TxDrop),
			"tx_byte_rate":      int64(deltaStats.TxByteRate),
			"tx_packet_rate":    int64(deltaStats.TxPacketRate),
			"tx_drop_rate":      float64(deltaStats.TxDropRate),
			"tx_error_rate":     float64(deltaStats.TxErrorRate),
		}, stats.SampleTime)

		netHistMtx.Lock()
		netHist[cg.Cgroup] = NetHistory{
			stats:      stats,
			sampleTime: stats.SampleTime,
		}
		netHistMtx.Unlock()
	} else {
		log.Printf("Error on cgroup sampling: %s\n", err)
	}
}

func collectBlkio(cg CgroupConfig, tags map[string]string, batch MeasurementBatch) {
	stats, err := cgroups.GetBlkioStats(cgroups.Cgroup{
		Root:   ctx.config.CgroupRoot,
		Cgroup: cg.Cgroup,
	})

	if err == nil {
		var deltaStats cgroups.BlkioDeltaStat

		blkioHistMtx.RLock()
		if hist, ok := blkioHist[cg.Cgroup]; ok {
			deltaStats = stats.Delta(hist.stats)
		}
		blkioHistMtx.RUnlock()

		log.Printf("stats: %+v\n", stats)
		log.Printf("deltaStats: %+v\n", deltaStats)

		batch.AddPoint("net", tags, map[string]interface{}{
			"merged":                 int64(stats.Merged),
			"queued":                 int64(stats.Queued),
			"rd_bytes":               int64(stats.ServiceBytesRead),
			"wr_bytes":               int64(stats.ServiceBytesWrite),
			"bytes":                  int64(stats.ServiceBytes),
			"rd_io":                  int64(stats.ServicedRead),
			"wr_io":                  int64(stats.ServicedWrite),
			"io":                     int64(stats.Serviced),
			"service_time_us":        int64(stats.ServiceTime / 1000),
			"wait_time_us":           int64(stats.WaitTime / 1000),
			"avg_service_time_ns":    int64(deltaStats.AvgServiceTimeNs),
			"rd_avg_service_time_ns": int64(deltaStats.AvgServiceTimeReadNs),
			"wr_avg_service_time_ns": int64(deltaStats.AvgServiceTimeWriteNs),
			"avg_wait_time_ns":       int64(deltaStats.AvgWaitTimeNs),
			"rd_avg_wait_time_ns":    int64(deltaStats.AvgWaitTimeReadNs),
			"wr_avg_wait_time_ns":    int64(deltaStats.AvgWaitTimeWriteNs),
			"rd_byte_rate":           int64(deltaStats.ByteRateRead),
			"wr_byte_rate":           int64(deltaStats.ByteRateWrite),
			"byte_rate":              int64(deltaStats.ByteRate),
			"rd_io_rate":             int64(deltaStats.IoRateRead),
			"wr_io_rate":             int64(deltaStats.IoRateWrite),
			"io_rate":                int64(deltaStats.IoRate),
		}, stats.SampleTime)

		blkioHistMtx.Lock()
		blkioHist[cg.Cgroup] = BlkioHistory{
			stats:      stats,
			sampleTime: stats.SampleTime,
		}
		blkioHistMtx.Unlock()
	} else {
		log.Printf("Error on cgroup sampling: %s\n", err)
	}
}

func collectOne(cg CgroupConfig, tags map[string]string, batch MeasurementBatch) {
	tags["cgroup"] = cg.Cgroup

	for k,v := range cg.Tags {
		tags[k] = v
	}

	log.Printf("root: %s\n", ctx.config.CgroupRoot)
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		collectCpu(cg, tags, batch)
		wg.Done()
	}()
	go func() {
		collectNet(cg, tags, batch)
		wg.Done()
	}()
	go func() {
		collectBlkio(cg, tags, batch)
		wg.Done()
	}()

	wg.Wait()

}

func collectAll(cgs []CgroupConfig) {
	var wg sync.WaitGroup
	var batch MeasurementBatchInflux

	batch.points = make([]*client.Point, 0, 32)

	wg.Add(len(cgs))
	for i := range cgs {
		cg := cgs[i]
		go func() {
			randJitterMs, err := rand.Int(rand.Reader,
			    big.NewInt(int64(10 + 1000 * ctx.config.JitterSecs)))
			if err != nil {
				randJitterMs = big.NewInt(0)
			}
			jitterMs := randJitterMs.Int64()
			time.Sleep(time.Duration(jitterMs) * time.Millisecond)
			fmt.Printf("Cgroup: %s, jitterMs: %d\n", cg.Cgroup, jitterMs)
			collectOne(cg, ctx.config.Tags, &batch)
			wg.Done()
		}()
	}

	wg.Wait()

	batchPoints, err := client.NewBatchPoints(client.BatchPointsConfig{
		Database:  globalFlags.InfluxDatabase,
		Precision: "s",
	})
	if err != nil {
		log.Printf("Error on NewBatchPoints(): %s\n", err)
		return
	}

	for i := range batch.points {
		batchPoints.AddPoint(batch.points[i])
	}

	err = ctx.influxClient.Write(batchPoints)
	if err != nil {
		log.Printf("Error on NewBatchPoints(): %s\n", err)
	}
}

func Collector() {
	var ticker *time.Ticker
	for {
		if ctx.config.IntervalSecs <= 0 {
			time.Sleep(1 * time.Second)
			continue
		}

		if ticker == nil {
			ticker = time.NewTicker(time.Duration(ctx.config.IntervalSecs) * time.Second)
		}

		select {
		case _ = <-ctx.changeChan:
			ticker.Stop()
			ticker = nil

		case _ = <-ticker.C:
			ctx.Lock()
			cgs := ctx.cgs
			ctx.Unlock()

			collectAll(cgs)
		}
	}
	ctx.wg.Done()
}

var RootCmd = &cobra.Command{
	Use:   "cgroups-influx [command]",
	Short: "",
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		ctx.influxClient, err = client.NewHTTPClient(client.HTTPConfig{
			Addr: globalFlags.InfluxURI,
			Username: globalFlags.InfluxUser,
			Password: globalFlags.InfluxPassword,
			Timeout: 5*time.Second,
			InsecureSkipVerify: globalFlags.InfluxTLSNoVerify,
		})

		if err != nil {
			log.Fatalln("Error: ", err)
		}

		// println("missing command")
		// cmd.HelpFunc()(cmd, args)
		ctx.config.CgroupRoot = globalFlags.CgroupRoot
		ctx.config.JitterSecs = 1
		ctx.wg.Add(2)
		go ConfigWatcher()
		go Collector()
		ctx.wg.Wait()
	},
}

func init() {
	RootCmd.PersistentFlags().StringVar(&globalFlags.CgroupRoot, "cgroup-root", globalFlags.CgroupRoot, "cgroups root path")
	RootCmd.PersistentFlags().StringVar(&globalFlags.StoreType, "store", globalFlags.StoreType, "Backend store type (etcd, consul, zk)")
	RootCmd.PersistentFlags().StringVar(&globalFlags.StoreURI, "store-uri", globalFlags.StoreURI, "Backend store URI")
	RootCmd.PersistentFlags().StringVar(&globalFlags.StoreBase, "store-base", globalFlags.StoreBase, "Backend store base path")
	RootCmd.PersistentFlags().StringVar(&globalFlags.StoreUser, "store-user", globalFlags.StoreUser, "Backend store username. If not specified, it will be taken from the ETCD_USER, CONSUL_USER or ZK_USER environment variables.")
	RootCmd.PersistentFlags().StringVar(&globalFlags.StorePassword, "store-pass", globalFlags.StorePassword, "Backend store password. If not specified, it will be taken from the ETCD_PASS, CONSUL_PASS or ZK_PASS environment variables.")
	RootCmd.PersistentFlags().BoolVar(&globalFlags.StoreTLSNoVerify, "store-no-verify", globalFlags.StoreTLSNoVerify, "Disable TLS certificate verification for backend store connection")
	RootCmd.PersistentFlags().BoolVar(&globalFlags.StoreUseTLS, "store-use-tls", globalFlags.StoreUseTLS, "Enable TLS-secured connection")

	RootCmd.PersistentFlags().StringVar(&globalFlags.InfluxURI, "influx-uri", globalFlags.InfluxURI, "Influx URI")
	RootCmd.PersistentFlags().StringVar(&globalFlags.InfluxDatabase, "influx-database", globalFlags.InfluxDatabase, "Influx database")
	RootCmd.PersistentFlags().StringVar(&globalFlags.InfluxUser, "influx-user", globalFlags.InfluxUser, "Influx username. If not specified, it will be taken from the INFLUX_USER environment variable.")
	RootCmd.PersistentFlags().StringVar(&globalFlags.InfluxPassword, "influx-pass", globalFlags.InfluxPassword, "Influx password. If not specified, it will be taken from the INFLUX_PASS environment variable.")
	RootCmd.PersistentFlags().BoolVar(&globalFlags.InfluxTLSNoVerify, "influx-no-verify", globalFlags.InfluxTLSNoVerify, "Disable TLS certificate verification for Influx connection")

	RootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if globalFlags.StoreUser == "" {
			globalFlags.StoreUser = os.Getenv(strings.ToUpper(globalFlags.StoreType) + "_USER")
		}
		if globalFlags.StorePassword == "" {
			globalFlags.StorePassword = os.Getenv(strings.ToUpper(globalFlags.StoreType) + "_PASS")
		}

		if globalFlags.InfluxUser == "" {
			globalFlags.StoreUser = os.Getenv("INFLUX_USER")
		}
		if globalFlags.InfluxPassword == "" {
			globalFlags.StorePassword = os.Getenv("INFLUX_PASS")
		}
	}

	consul.Register()
	etcd.Register()
	zookeeper.Register()
}

func main() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
