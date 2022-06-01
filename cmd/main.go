// Copyright 2020 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Heavily based on github.com/prometheus-community/json_exporter

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus-community/json_exporter/config"
	"github.com/prometheus-community/json_exporter/exporter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	"gopkg.in/alecthomas/kingpin.v2"
	"net/http"
	"os"
)

var (
	bpfMapName    = kingpin.Flag("bpf_map.name", "Name of BPF map to read JSON from.").Default("pscan_stats").String()
	configFile    = kingpin.Flag("config.file", "JSON exporter configuration file.").Default("config/config.yml").ExistingFile()
	configCheck   = kingpin.Flag("config.check", "If true validate the config file and then exit.").Default("false").Bool()
	listenAddress = kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests.").Default(":7979").String()
	tlsConfigFile = kingpin.Flag("web.config", "[EXPERIMENTAL] Path to config yaml file that can enable TLS or authentication.").Default("").String()
)

func Run() {
	promlogConfig := &promlog.Config{}

	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("bpf_portscan_stats"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting BPF portscan stats exporter")

	level.Info(logger).Log("msg", "Loading BPF map", "map", *bpfMapName)

	level.Info(logger).Log("msg", "Loading configRaw file", "file", *configFile)
	configRaw, err := config.LoadConfig(*configFile)
	if err != nil {
		level.Error(logger).Log("msg", "Error loading configRaw", "err", err)
		os.Exit(1)
	}
	configJSON, err := json.Marshal(configRaw)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to marshal configRaw to JSON", "err", err)
	}
	level.Info(logger).Log("msg", "Loaded configRaw file", "configRaw", string(configJSON))

	if *configCheck {
		os.Exit(0)
	}

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/probe", func(w http.ResponseWriter, req *http.Request) {
		probeHandler(w, req, logger, configRaw)
	})

	server := &http.Server{Addr: *listenAddress}
	if err := web.ListenAndServe(server, *tlsConfigFile, logger); err != nil {
		level.Error(logger).Log("msg", "Failed to start the server", "err", err)
		os.Exit(1)
	}
}

func probeHandler(w http.ResponseWriter, r *http.Request, logger log.Logger, configRaw config.Config) {

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	r = r.WithContext(ctx)

	module := r.URL.Query().Get("module")
	if module == "" {
		module = "default"
	}
	if _, ok := configRaw.Modules[module]; !ok {
		http.Error(w, fmt.Sprintf("Unknown module %q", module), http.StatusBadRequest)
		level.Debug(logger).Log("msg", "Unknown module", "module", module)
		return
	}

	registry := prometheus.NewPedanticRegistry()

	metrics, err := exporter.CreateMetricsList(configRaw.Modules[module])
	if err != nil {
		level.Error(logger).Log("msg", "Failed to create metrics list from configRaw", "err", err)
	}

	jsonMetricCollector := exporter.JSONMetricCollector{JSONMetrics: metrics}
	jsonMetricCollector.Logger = logger

	data, err := dumpBPFMap(*bpfMapName, logger)
	if err != nil {
		http.Error(w, "Failed to fetch JSON. ERROR: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	jsonMetricCollector.Data = data

	registry.MustRegister(jsonMetricCollector)
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func dumpBPFMap(mapName string, logger log.Logger) ([]byte, error) {
	/* Shortcut: kernel presents the BTFied maps contents in a JSON format through `bpftool`
	   I briefly tried various libbpf / ebpf etc. golang libs, but all seem to be non-trivial and fail
	   in non-obvious ways while loading the bpf module object. Thus, fallback to exec `bpftool` */
	bpftoolCmd := "/usr/sbin/bpftool"
	bpfToolArgs := []string{"map", "dump", "name", *bpfMapName}
	level.Info(logger).Log("msg", "bpftool command", "command", bpftoolCmd)
	level.Info(logger).Log("msg", "bpftool args", "args", strings.Join(bpfToolArgs[:], " "))
	statsJson, err := exec.Command(bpftoolCmd, bpfToolArgs...).Output()
	if err != nil {
		level.Error(logger).Log("msg", "Failed to dump BPF map", "map", *bpfMapName)
		level.Error(logger).Log("msg", "error was", "err", err)
	}
	level.Info(logger).Log("msg", "bpftool output was", "stdout+stderr", statsJson) //TODO: debug logging
	return statsJson, err
}
