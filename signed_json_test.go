package signedjson

import (
	"testing"
)

func TestSignJSON(t *testing.T) {
	o := map[string]interface{}{
		"foo": "bar",
	}
	key, err := New("1")
	if err != nil {
		t.Fatal(err)
	}
	err = key.Sign(o, "Alice")
	if err != nil {
		t.Fatal(err)
	}

	err = key.Verify(o, "Alice")
	if err != nil {
		t.Fatal(err)
	}
}
