package encrypt

import (
	"testing"
)

// const (
// 	Ecb = 1 //电码本模式
// 	Cbc = 2 //密码分组链接模式
// 	Ctr = 3 //计算器模式
// 	Cfb = 4 //密码反馈模式
// 	Ofb = 5 //输出反馈模式
// )

func TestAES_Encrypt(t *testing.T) {
	src := []byte("hello world")
	key := []byte("1443flfsaWfdas12")
	// code, _ := asc.Encrypt(src, key)
	// want, _ := asc.Encrypt(code, key)

	type fields struct {
		mode int
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name:   "ECB 电码本模式",
			fields: fields{mode: 1},
		},
		{
			name:   "CBC 密码分组链接模式",
			fields: fields{mode: 2},
		},
		{
			name:   "CTR 计算器模式",
			fields: fields{mode: 3},
		},
		{
			name:   "CFB 密码反馈模式",
			fields: fields{mode: 4},
		},
		{
			name:   "OFB 输出反馈模式",
			fields: fields{mode: 5},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAES()
			a.SetMode(tt.fields.mode)
			got, err := a.Encrypt(src, key)
			if err != nil {
				t.Errorf("AES.Encrypt() error = %v", err)
				return
			}
			want, err := a.Decrypt(got, key)
			if err != nil {
				t.Errorf("AES.Decrypt() error = %v", err)
				return
			}

			if string(src) != string(want) {
				t.Errorf("AES.Decrypt()-%d = %v, want= %v", tt.fields.mode, string(src), string(want))
			}
		})
	}
}
