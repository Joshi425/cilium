// Copyright 2019-2020 Authors of Hubble
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

// +build !privileged_tests

package filters

import (
	"context"
	"testing"

	pb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func Test_filterByReplyField(t *testing.T) {
	type args struct {
		f  []*pb.FlowFilter
		ev *v1.Event
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    bool
	}{
		{
			name: "nil flow",
			args: args{
				f:  []*pb.FlowFilter{{Reply: []bool{true}}},
				ev: &v1.Event{},
			},
			want: false,
		},
		{
			name: "empty-param",
			args: args{
				f:  []*pb.FlowFilter{{Reply: []bool{}}},
				ev: &v1.Event{Event: &pb.Flow{Reply: true}},
			},
			want: true,
		},
		{
			name: "empty-param-2",
			args: args{
				f:  []*pb.FlowFilter{{Reply: []bool{}}},
				ev: &v1.Event{Event: &pb.Flow{Reply: false}},
			},
			want: true,
		},
		{
			name: "no-reply",
			args: args{
				f:  []*pb.FlowFilter{{Reply: []bool{false}}},
				ev: &v1.Event{Event: &pb.Flow{Reply: false}},
			},
			want: true,
		},
		{
			name: "reply",
			args: args{
				f:  []*pb.FlowFilter{{Reply: []bool{true}}},
				ev: &v1.Event{Event: &pb.Flow{Reply: true}},
			},
			want: true,
		},
		{
			name: "no-match",
			args: args{
				f:  []*pb.FlowFilter{{Reply: []bool{true}}},
				ev: &v1.Event{Event: &pb.Flow{Reply: false}},
			},
			want: false,
		},
		{
			name: "no-match-2",
			args: args{
				f:  []*pb.FlowFilter{{Reply: []bool{false}}},
				ev: &v1.Event{Event: &pb.Flow{Reply: true}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&ReplyFilter{}})
			if (err != nil) != tt.wantErr {
				t.Errorf("\"%s\" error = %v, wantErr %v", tt.name, err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if got := fl.MatchOne(tt.args.ev); got != tt.want {
				t.Errorf("\"%s\" got %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
