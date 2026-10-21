// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

// Backport of `kubectl ate update actor --template` (upstream #2814) onto the
// v0.4.0 client, so it speaks the v0.4.0 wire format. Template only: the
// worker-selector half of #2814 is not carried.

import (
	"context"
	"fmt"

	"github.com/agent-substrate/substrate/cmd/kubectl-ate/internal/printer"
	"github.com/agent-substrate/substrate/internal/ateclient"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

var (
	updateActorAtespaceFlag string
	updateActorTemplateFlag string
)

var updateActorCmd = &cobra.Command{
	Use:   "actor <actor-name>",
	Short: "Repoint an actor at another actor-template",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if updateActorTemplateFlag == "" {
			return fmt.Errorf("--template is required")
		}
		templateRef, err := parseAtespacedName(updateActorTemplateFlag, updateActorAtespaceFlag)
		if err != nil {
			return err
		}

		ctx := cmd.Context()
		apiClient, err := ateclient.NewClient(ctx, kubeconfig, k8sContext, endpoint, tokenFile, traceEnabled)
		if err != nil {
			return fmt.Errorf("failed to connect to ate-api-server: %w", err)
		}
		defer apiClient.Close()

		ref := &ateapipb.ObjectRef{Atespace: updateActorAtespaceFlag, Name: args[0]}
		resp, err := updateActor(ctx, apiClient, ref, func(actor *ateapipb.Actor) {
			actor.ActorTemplate = templateRef
		})
		if err != nil {
			return err
		}
		return printer.PrintActorTo(cmd.OutOrStdout(), resp, outputFmt)
	},
}

type actorUpdater interface {
	GetActor(ctx context.Context, in *ateapipb.GetActorRequest, opts ...grpc.CallOption) (*ateapipb.Actor, error)
	UpdateActor(ctx context.Context, in *ateapipb.UpdateActorRequest, opts ...grpc.CallOption) (*ateapipb.Actor, error)
}

// updateActor is a read-modify-write: the fetched actor carries the
// metadata version and uid the server requires as preconditions.
func updateActor(ctx context.Context, client actorUpdater, ref *ateapipb.ObjectRef, mutate func(*ateapipb.Actor)) (*ateapipb.Actor, error) {
	actor, err := client.GetActor(ctx, &ateapipb.GetActorRequest{Actor: ref})
	if err != nil {
		return nil, fmt.Errorf("failed to get actor %q: %w", ref.GetName(), err)
	}
	mutate(actor)
	resp, err := client.UpdateActor(ctx, &ateapipb.UpdateActorRequest{Actor: actor})
	if err != nil {
		return nil, fmt.Errorf("failed to update actor: %w", err)
	}
	return resp, nil
}

func init() {
	updateActorCmd.Flags().StringVarP(&updateActorAtespaceFlag, "atespace", "a", "", "the actor's atespace")
	updateActorCmd.Flags().StringVar(&updateActorTemplateFlag, "template", "", "actor-template to repoint the actor to, as <atespace>/<template-name>, or just <template-name> to use the actor's own atespace (see --atespace)")
	updateCmd.AddCommand(updateActorCmd)
}
