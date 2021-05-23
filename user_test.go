package security

import "testing"

func TestUser_HasGroup(t *testing.T) {
	type fields struct {
		EMail  string
		Name   string
		Groups []ResourceAccess
	}
	type args struct {
		grps []ResourceAccess
	}
	inputfield := fields{
		EMail: "blubber",
		Name:  "blabber",
		Groups: []ResourceAccess{
			ResourceAccess("a"),
			ResourceAccess("b"),
			ResourceAccess("c"),
		},
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name:   "no group in groups",
			fields: inputfield,
			args: args{
				grps: []ResourceAccess{
					ResourceAccess("1"),
					ResourceAccess("2"),
					ResourceAccess("3"),
				},
			},
			want: false,
		},
		{
			name:   "one group in groups",
			fields: inputfield,
			args: args{
				grps: []ResourceAccess{
					ResourceAccess("1"),
					ResourceAccess("a"),
					ResourceAccess("3"),
				},
			},
			want: true,
		},
		{
			name:   "multiple groups in groups",
			fields: inputfield,
			args: args{
				grps: []ResourceAccess{
					ResourceAccess("1"),
					ResourceAccess("a"),
					ResourceAccess("b"),
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			u := &User{
				EMail:  tt.fields.EMail,
				Name:   tt.fields.Name,
				Groups: tt.fields.Groups,
			}
			if got := u.HasGroup(tt.args.grps...); got != tt.want {
				t.Errorf("User.HasGroup() = %v, want %v", got, tt.want)
			}
		})
	}
}
