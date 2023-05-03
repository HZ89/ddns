package main

import (
	"reflect"
	"testing"
)

func TestConnection_SendCommands(t *testing.T) {
	type fields struct {
		ipaddr string
		user string
		password string
	}
	type args struct {
		cmds []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "tt-1",
			fields: fields{
				ipaddr: "192.168.31.1:22",
				user: "root",
				password: "202598a1Z",
			},
			args: args{
				cmds: []string{`echo -n hello`},
			},
			want: []byte("hello"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := Connect(tt.fields.ipaddr, tt.fields.user, tt.fields.password)
			if err != nil {
				t.Errorf("Create Connection failed: %v", err)
			}
			got, err := conn.SendCommands(tt.args.cmds...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.SendCommands() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Connection.SendCommands() = %v, want %v", got, tt.want)
			}
		})
	}
}
