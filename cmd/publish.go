package cmd

import (
	"encoding/json"
	"net/http"

	dp1 "github.com/display-protocol/dp1-go"
	"github.com/spf13/cobra"

	"github.com/display-protocol/dp1-cli/internal/config"
	"github.com/display-protocol/dp1-cli/internal/feed"
	"github.com/display-protocol/dp1-cli/internal/input"
	"github.com/display-protocol/dp1-cli/internal/output"
)

var publishFeedURL string

var playlistPublishCmd = &cobra.Command{
	Use:   "publish <source>",
	Short: "Validate playlist JSON and POST it to the feed API (create)",
	Args:  cobra.ExactArgs(1),
	RunE:  runPlaylistPublish,
}

var channelPublishCmd = &cobra.Command{
	Use:   "publish <source>",
	Short: "Validate channel JSON and POST it to the feed API (create)",
	Args:  cobra.ExactArgs(1),
	RunE:  runChannelPublish,
}

var groupPublishCmd = &cobra.Command{
	Use:   "publish <source>",
	Short: "Validate playlist-group JSON and POST it to the feed API (create)",
	Args:  cobra.ExactArgs(1),
	RunE:  runGroupPublish,
}

func init() {
	for _, c := range []*cobra.Command{playlistPublishCmd, channelPublishCmd, groupPublishCmd} {
		c.Flags().StringVar(&publishFeedURL, "feed-url", "", "Feed base URL (overrides "+feed.EnvURL+" and config feed.url)")
	}

	playlistCmd.AddCommand(playlistPublishCmd)
	channelCmd.AddCommand(channelPublishCmd)
	groupCmd.AddCommand(groupPublishCmd)
}

func runPlaylistPublish(cmd *cobra.Command, args []string) error {
	return runPublish(cmd, args[0], "playlist publish", "playlist", feed.Playlist, func(b []byte) error {
		_, err := dp1.ParseAndValidatePlaylist(b)
		return err
	})
}

func runChannelPublish(cmd *cobra.Command, args []string) error {
	return runPublish(cmd, args[0], "channel publish", "channel", feed.Channel, func(b []byte) error {
		_, err := dp1.ParseAndValidateChannel(b)
		return err
	})
}

func runGroupPublish(cmd *cobra.Command, args []string) error {
	return runPublish(cmd, args[0], "group publish", "playlist-group", feed.PlaylistGroup, func(b []byte) error {
		_, err := dp1.ParseAndValidatePlaylistGroup(b)
		return err
	})
}

func runPublish(cmd *cobra.Command, source, commandName, resourceLabel string, path feed.Resource, validate func([]byte) error) error {
	data, err := input.ReadSource(cmd.Context(), source)
	if err != nil {
		output.PrintError(jsonOut, output.ErrorReport{Command: commandName, Error: err.Error()})
		return errPrinted
	}
	if err := validate(data); err != nil {
		output.PrintError(jsonOut, output.ErrorReport{Command: commandName, Error: err.Error()})
		return errPrinted
	}

	cfg, err := config.LoadCached()
	if err != nil {
		output.PrintError(jsonOut, output.ErrorReport{Command: commandName, Error: err.Error()})
		return errPrinted
	}
	base, err := feed.ResolveBaseURL(publishFeedURL, cfg.Feed)
	if err != nil {
		output.PrintError(jsonOut, output.ErrorReport{Command: commandName, Error: err.Error()})
		return errPrinted
	}

	client := feed.NewClient()
	status, respBody, err := client.Create(cmd.Context(), base, path, data)
	if err != nil {
		output.PrintError(jsonOut, output.ErrorReport{Command: commandName, Error: err.Error()})
		return errPrinted
	}
	if status != http.StatusCreated {
		apiErr := feed.ErrorFromResponse(status, respBody)
		output.PrintError(jsonOut, output.ErrorReport{Command: commandName, Error: apiErr.Error()})
		return errPrinted
	}

	raw := json.RawMessage(respBody)
	output.PrintPublishSuccess(jsonOut, output.PublishOK{
		Resource:   resourceLabel,
		Feed:       base,
		StatusCode: status,
		Response:   raw,
	})
	return nil
}
