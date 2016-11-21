// MIT License
// -----------
//
// Copyright (c) 2016 Tony Zou
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, // and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER // LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package flexvolume

import (
	"encoding/json"
	"fmt"
	"os"
)

type Response struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Device  string `json:"device,omitempty"`
}

type DefaultOptions struct {
	ApiKey string `json:"kubernetes.io/secret/apiKey"`
	FsType string `json:"kubernetes.io/fsType"`
}

type FlexVolumePlugin interface {
	NewOptions() interface{}
	Init() Response
	Attach(opt interface{}) Response
	Detach(device string) Response
	Mount(mountDir string, device string, opt interface{}) Response
	Unmount(mountDir string) Response
}

func Succeed(a ...interface{}) Response {
	return Response{
		Status:  "Success",
		Message: fmt.Sprint(a...),
	}
}

func Fail(a ...interface{}) Response {
	return Response{
		Status:  "Failure",
		Message: fmt.Sprint(a...),
	}
}

func finish(Response Response) {
	code := 1
	if Response.Status == "Success" {
		code = 0
	}
	res, err := json.Marshal(Response)
	if err != nil {
		fmt.Println("{\"status\":\"Failure\",\"message\":\"JSON error\"}")
	} else {
		fmt.Println(string(res))
	}
	os.Exit(code)
}

func RunPlugin(plugin FlexVolumePlugin) {
	if len(os.Args) < 2 {
		finish(Fail("Expected at least one argument"))
	}

	switch os.Args[1] {
	case "init":
		finish(plugin.Init())

	case "attach":
		if len(os.Args) != 3 {
			finish(Fail("attach expected exactly 3 arguments; got ", os.Args))
		}

		opt := plugin.NewOptions()
		if err := json.Unmarshal([]byte(os.Args[2]), opt); err != nil {
			finish(Fail("Could not parse options for attach; got ", os.Args[2]))
		}

		finish(plugin.Attach(opt))

	case "detach":
		if len(os.Args) != 3 {
			finish(Fail("detach expected exactly 3 arguments; got ", os.Args))
		}

		device := os.Args[2]
		finish(plugin.Detach(device))

	case "mount":
		if len(os.Args) != 5 {
			finish(Fail("mount expected exactly 5 argument; got ", os.Args))
		}

		mountDir := os.Args[2]
		device := os.Args[3]

		opt := plugin.NewOptions()
		if err := json.Unmarshal([]byte(os.Args[4]), opt); err != nil {
			finish(Fail("Could not parse options for attach; got ", os.Args[2]))
		}

		finish(plugin.Mount(mountDir, device, opt))

	case "unmount":
		if len(os.Args) != 3 {
			finish(Fail("mount expected exactly 5 argument; got ", os.Args))
		}

		mountDir := os.Args[2]

		finish(plugin.Unmount(mountDir))

	default:
		finish(Fail("Not sure what to do. Called with: ", os.Args))
	}

}
