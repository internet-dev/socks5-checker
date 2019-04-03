package main

import (
	"flag"
	"fmt"
	"os"
	"sync"

	"bufio"
	"io"
	"strings"

	"github.com/astaxie/beego/logs"
	"github.com/erikdubbelboer/gspt"
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

func Strim(str string) string {
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
	for i := 0; i < 4; i++ {
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

		line = Strim(line)
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
	}
}
