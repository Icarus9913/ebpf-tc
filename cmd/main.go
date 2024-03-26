package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	bpf_map "ebpf-tc/bpf-map"
)

var (
	binName               = filepath.Base(os.Args[0])
	originalAddr, newAddr string
)

func main() {
	{
		// the add cmd requires "original-address" and "new-address"
		addCmd.PersistentFlags().StringVarP(&originalAddr, "original-address", "", "", "original IP address")
		addCmd.PersistentFlags().StringVarP(&newAddr, "new-address", "", "", "new IP address")
		_ = addCmd.MarkPersistentFlagRequired("original-address")
		_ = addCmd.MarkPersistentFlagRequired("new-address")

		// the del cmd just requires "original-address"
		delCmd.PersistentFlags().StringVarP(&originalAddr, "original-address", "", "", "original IP address")
		_ = delCmd.MarkPersistentFlagRequired("original-address")
	}

	rootCmd.AddCommand(addCmd, delCmd, listCmd)
	err := rootCmd.Execute()
	if nil != err {
		log.Fatal(err)
	}
}

// rootCmd represents the base command.
var rootCmd = &cobra.Command{
	Use: binName,
	CompletionOptions: cobra.CompletionOptions{
		HiddenDefaultCmd: true,
	},
}

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "add original and new IP address data to ebpf map",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Add: original-address '%s', new-address '%s'\n", originalAddr, newAddr)

		mapper, err := bpf_map.NewMapper()
		if nil != err {
			log.Fatal(err)
		}

		err = mapper.Set(bpf_map.NewMapKey(bpf_map.Ipv4ToUint32(originalAddr)), bpf_map.NewMapValue(bpf_map.Ipv4ToUint32(newAddr)))
		if nil != err {
			log.Fatal(err)
		}
		fmt.Printf("")
	},
}

var delCmd = &cobra.Command{
	Use:   "del",
	Short: "delete original IP address data from ebpf map",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Del: original-address '%s'\n", originalAddr)

		mapper, err := bpf_map.NewMapper()
		if nil != err {
			log.Fatal(err)
		}

		err = mapper.Del(bpf_map.NewMapKey(bpf_map.Ipv4ToUint32(originalAddr)))
		if nil != err {
			log.Fatal(err)
		}
		fmt.Printf("delete ebpf ")
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "list ebpf map data",
	Run: func(cmd *cobra.Command, args []string) {
		mapper, err := bpf_map.NewMapper()
		if nil != err {
			log.Fatal(err)
		}

		mapCache, _ := mapper.List()
		log.Printf("ebpf map list: %v", mapCache)
	},
}
