package secure

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestTokenCannotSerializeOrPrint(t *testing.T) {
	v := NewToken("PRIVATE_AUTH_CANARY")
	if _, e := json.Marshal(v); e == nil {
		t.Fatal("serialized token")
	}
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		if strings.Contains(fmt.Sprintf(f, v), "PRIVATE_AUTH_CANARY") {
			t.Fatal("formatted token")
		}
	}
}
func TestTextControlRemoval(t *testing.T) {
	if Text("x\x1b\n\u202ey") != "xy" {
		t.Fatal("control escape failed")
	}
}
