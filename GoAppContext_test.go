package GoAppContext

import "testing"

func TestinitApplicationHandlerContext(t *testing.T) {
	app, err := initApplicationHandlerContext("testname", "dummy private key goes here.....")
	if err != nil {
		t.Error("Error returned: ", err)
	}

	if app.ApplicationName == "" {
		t.Error("Application Handler Context init failed")
	}
}

/*
func TestAdd(t *testing.T) {
	a := 1
	b := 2
	expected := a + b

	if got := Add(a, b); got != expected {
		t.Errorf("Add(%d, %d) = %d, didn't return %d", a, b, got, expected)
	}
}

func TestSubtract(t *testing.T) {
	a := 1
	b := 2
	expected := a - b

	if got := Subtract(a, b); got != expected {
		t.Errorf("Subtract(%d, %d) = %d, didn't return %d", a, b, got, expected)
	}
}
*/
