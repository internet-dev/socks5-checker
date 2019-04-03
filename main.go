package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/astaxie/beego/logs"
	"github.com/erikdubbelboer/gspt"
	"golang.org/x/net/proxy"
)

const programName = "socks5-checker"

// 事件广播 {

var done = make(chan struct{})

func cancelled() bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// }

type WorkArgsT struct {
	InputFile  string
	OutputFile string
	Help       bool

	Mutex   sync.Mutex // 读写锁,多协程同时写文件
	Queue   chan string
	inputFd *os.File
}

type Context struct {
	OutputFd *os.File
	RwLock   *sync.Mutex
}

var workArgs WorkArgsT
var ctx Context

func init() {
	flag.StringVar(&workArgs.InputFile, "input-file", "", "need check socks5 list file")
	flag.StringVar(&workArgs.OutputFile, "output-file", "", "valid list file")
	flag.BoolVar(&workArgs.Help, "h", false, "show usage and exit")

	flag.Usage = usage
}

func errMsg(msg string, code int) {
	fmt.Fprintln(os.Stdout, msg)

	if code != 0 {
		os.Exit(code)
	}
}

func usage() {
	fmt.Fprintf(os.Stdout, programName+`
Usage:
  ./%s -h
  ./%s -input-file=need-check -output-file=valid-list
`, programName, programName)

	flag.PrintDefaults()
	os.Exit(0)
}

func main() {
	flag.Parse()

	if workArgs.Help {
		flag.Usage()
	}

	//logs.Debug("before init workArgs: %#v", workArgs)

	if workArgs.InputFile == "" || workArgs.OutputFile == "" {
		usage()
	}

	inputFd, err := os.Open(workArgs.InputFile)
	if err != nil {
		errMsg(fmt.Sprintf(`can not open input file: %s, err: %v`, workArgs.InputFile, err), 1)
	}
	workArgs.inputFd = inputFd
	defer inputFd.Close()

	outputFd, err := os.Create(workArgs.OutputFile)
	if err != nil {
		errMsg(fmt.Sprintf(`can not create output file: %s, err: %v`, workArgs.OutputFile, err), 2)
	}
	ctx.OutputFd = outputFd
	defer outputFd.Close()

	// 当队列使用
	workArgs.Queue = make(chan string)
	// 读写锁
	ctx.RwLock = &workArgs.Mutex

	//logs.Debug("after init workArgs: %#v", workArgs)

	gspt.SetProcTitle(programName)

	doCheck(&workArgs, &ctx)
}

func trim(str string) string {
	str = strings.Replace(str, "\t", "", -1)
	str = strings.Replace(str, " ", "", -1)
	str = strings.Replace(str, "\n", "", -1)
	str = strings.Replace(str, "\r", "", -1)

	return str
}

func doCheck(env *WorkArgsT, ctx *Context) {
	go produceQueue(env)

	var wg sync.WaitGroup
	// 可视情况加工作 goroutine 数
	for i := 0; i < 128; i++ {
		wg.Add(1)
		go consumeQueue(&wg, i, env, ctx)
	}

	// 主 goroutine,等待工作 goroutine 正常结束
	wg.Wait()

	logs.Informational("[doCheck] jobs has done")
}

func produceQueue(env *WorkArgsT) {
	buff := bufio.NewReader(env.inputFd) //读入缓存
	for {
		line, err := buff.ReadString('\n') //以'\n'为结束符读入一行
		if err != nil || io.EOF == err {
			break
		}

		line = trim(line)
		logs.Notice("[produceQueue] item: %s", line)
		env.Queue <- line
	}

	close(done)
	close(env.Queue)
}

func consumeQueue(wg *sync.WaitGroup, workerID int, env *WorkArgsT, ctx *Context) {
	defer wg.Done()

	logs.Informational("[consumeQueue] start work, workerID: %d", workerID)

	for {
		if cancelled() {
			logs.Informational("[consumeQueue] jobs has cancelled/complete, will exit normal, workID: %d", workerID)
			break
		}

		proxyConf := <-env.Queue
		if proxyConf == "" {
			continue
		}

		logs.Debug("[consumeQueue] workID: %d, proxyConf: %s", workerID, proxyConf)

		targetURL := "https://www.google.com"
		reqHeaders := map[string]string{
			"Connection": "keep-alive",
			"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
			"Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
		}
		_, httpStatusCode, errHttp := socks5Client(proxyConf, "GET", targetURL, reqHeaders, "")
		if errHttp != nil || httpStatusCode == 0 {
			logs.Error("[check-result] proxy: %s is invalid, status-code: %d, err: %v",
				proxyConf, httpStatusCode, errHttp)
		} else {
			ctx.RwLock.Lock()
			ctx.OutputFd.WriteString(proxyConf + "\n")
			ctx.RwLock.Unlock()
		}
		logs.Notice("[check-result] proxy: %s , status-code: %d, err: %v",
			proxyConf, httpStatusCode, errHttp)
	}
}

func socks5Client(proxyConf, reqMethod string, reqUrl string, reqHeaders map[string]string, reqBody string) ([]byte, int, error) {
	var httpStatusCode int
	var emptyBody []byte

	req, err := http.NewRequest(reqMethod, reqUrl, strings.NewReader(reqBody))
	if err != nil {
		logs.Error("[socks5Client] http.NewRequest fail, reqUrl:", reqUrl)
		return emptyBody, httpStatusCode, err
	}

	for k, v := range reqHeaders {
		req.Header.Set(k, v)
	}

	// Create a socks5 dialer
	dialer, err := proxy.SOCKS5("tcp", proxyConf, nil, proxy.Direct)
	if err != nil {
		logs.Error("[socks5Client] proxy dialer err: %v, proxyConf: %s", err, proxyConf)
	}

	// Setup HTTP transport
	tr := &http.Transport{
		Dial: dialer.Dial,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		logs.Error("[socks5Client] do request fail, reqUrl:", reqUrl, ", err:", err)
		return emptyBody, httpStatusCode, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logs.Error("[socks5Client] read request fail, reqUrl:", reqUrl, ", err:", err)
		return emptyBody, httpStatusCode, err
	}

	return body, resp.StatusCode, err
}
