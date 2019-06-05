package security

import "testing"

func TestUser_HasGroup(t *testing.T) {
	type fields struct {
		EMail  string
		Name   string
		Groups []RessourceAccess
	}
	type args struct {
		grps []RessourceAccess
	}
	inputfield := fields{
		EMail: "blubber",
		Name:  "blabber",
		Groups: []RessourceAccess{
			RessourceAccess("a"),
			RessourceAccess("b"),
			RessourceAccess("c"),
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
				grps: []RessourceAccess{
					RessourceAccess("1"),
					RessourceAccess("2"),
					RessourceAccess("3"),
				},
			},
			want: false,
		},
		{
			name:   "one group in groups",
			fields: inputfield,
			args: args{
				grps: []RessourceAccess{
					RessourceAccess("1"),
					RessourceAccess("a"),
					RessourceAccess("3"),
				},
			},
			want: true,
		},
		{
			name:   "multiple groups in groups",
			fields: inputfield,
			args: args{
				grps: []RessourceAccess{
					RessourceAccess("1"),
					RessourceAccess("a"),
					RessourceAccess("b"),
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
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
