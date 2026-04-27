package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	brutal "github.com/phuslu/tcp-brutal"
)

type loadOptions struct {
	brutal.Options
	foreground bool
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "load":
		var opts loadOptions
		opts, err = parseLoadArgs(os.Args[2:])
		if err == nil {
			err = runLoad(opts)
		}
	case "unload":
		var opts brutal.Options
		opts, err = parseUnloadArgs(os.Args[2:])
		if err == nil {
			err = brutal.UnloadWithOptions(opts)
			if err == nil {
				fmt.Println("TCP Brutal eBPF unloaded")
			}
		}
	default:
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  %s load [--cgroup PATH] [--force] [--foreground]
  %s unload [--cgroup PATH]

Defaults:
  --cgroup /sys/fs/cgroup
`, filepath.Base(os.Args[0]), filepath.Base(os.Args[0]))
}

func parseLoadArgs(args []string) (loadOptions, error) {
	opts := loadOptions{
		Options: brutal.Options{
			CgroupPath: "/sys/fs/cgroup",
		},
	}

	fs := flag.NewFlagSet("load", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&opts.CgroupPath, "cgroup", opts.CgroupPath, "cgroup v2 path")
	fs.BoolVar(&opts.Force, "force", false, "unload existing pins before loading if brutal is not already available")
	fs.BoolVar(&opts.foreground, "foreground", false, "wait in the foreground and unload on signal")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() != 0 {
		return opts, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return opts, nil
}

func parseUnloadArgs(args []string) (brutal.Options, error) {
	opts := brutal.Options{
		CgroupPath: "/sys/fs/cgroup",
	}

	fs := flag.NewFlagSet("unload", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&opts.CgroupPath, "cgroup", opts.CgroupPath, "cgroup v2 path")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() != 0 {
		return opts, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return opts, nil
}

func runLoad(opts loadOptions) error {
	if brutal.IsLoaded() {
		return nil
	}

	if err := brutal.LoadWithOptions(opts.Options); err != nil {
		return err
	}

	if !opts.foreground {
		fmt.Println("TCP Brutal eBPF loaded")
		return nil
	}

	fmt.Println("TCP Brutal eBPF loaded in foreground. Press Ctrl-C to unload.")
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	signal.Stop(ch)
	return brutal.UnloadWithOptions(opts.Options)
}
