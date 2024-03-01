package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	binName          = filepath.Base(os.Args[0])
	srcAddr, dstAddr string
)

func main() {
	rootCmd.PersistentFlags().StringVarP(&srcAddr, "source-address", "s", "", "source IP address")
	rootCmd.PersistentFlags().StringVarP(&dstAddr, "destination-address", "d", "", "destination IP address")
	_ = rootCmd.MarkPersistentFlagRequired("source-address")
	_ = rootCmd.MarkPersistentFlagRequired("destination-address")

	rootCmd.AddCommand(addCmd, delCmd)
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
	Short: "add source and destination IP address",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Add: source-address '%s', destination-address '%s'\n", srcAddr, dstAddr)
	},
}

var delCmd = &cobra.Command{
	Use:   "del",
	Short: "delete source and destination IP address",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Del: source-address '%s', destination-address '%s'\n", srcAddr, dstAddr)
	},
}
