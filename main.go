package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

func dateconvert(datein string) string {
	// Convert from: December 11,2020
	//   To: 12/11/2020

	var monthnames = [...]string{"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"}
	var monthnum = [...]string{"01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"}
	var month string

	//split input string by space and comma
	split1 := strings.Split(datein, " ")
	split2 := strings.Split(split1[1], ",")

	//pick off monthname, day, year from splits
	monthname := split1[0]
	day := split2[0]
	year := split2[1]

	// Convert month from Name to number
	month = "00"
	for i := range monthnames {
		//fmt.Printf("%d:%s:%s:%s\n", i, monthname, monthnames[i], monthnum[i])
		if monthnames[i] == monthname {
			month = monthnum[i]
			break
		}
	}

	// Put them together
	dateout := month + "/" + day + "/" + year

	return dateout
}

func main() {

	var Conn, Dos, Other int
	var Linetype string

	rxconn := regexp.MustCompile(`\[DHCP IP: \(([0-9.]*)\)] to MAC address ([0-9A-F:]*), [A-Z][a-z]*, ([A-Z][a-z]* [0-9]*,[0-9]*) ([0-9]*:[0-9]*:[0-9]*)`)
	rxdos := regexp.MustCompile(`\[DoS attack: ([a-zA-Z ]*)\] from source: ([0-9.]*):([0-9]*), [A-Z][a-z]*, ([A-Z][a-z]* [0-9]*,[0-9]*) ([0-9]*:[0-9]*:[0-9]*)`)

	// Get and format the current date and time for printing
	dt := time.Now()
	prtdt := fmt.Sprintf("%s", dt.Format("01-02-2006 15:04:05"))
	fmt.Printf("[%s] Reading Netgear network log\n", prtdt)

	// Read lines of input from file
	file, err := os.Open("test.data")
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	defer file.Close()

	// open output files to append lines
	ofconn, err := os.OpenFile("connections.csv", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	defer ofconn.Close()

	ofdos, err := os.OpenFile("dos.csv", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	defer ofdos.Close()
	ofoth, err := os.OpenFile("other.txt", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	defer ofoth.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		linein := scanner.Text()

		Linetype = "O"

		matchconn := rxconn.FindStringSubmatchIndex(linein)
		if len(matchconn) == 10 {
			Conn++
			Linetype = "C"
			ip := string(linein[matchconn[2]:matchconn[3]])
			mac := string(linein[matchconn[4]:matchconn[5]])
			date := string(linein[matchconn[6]:matchconn[7]])
			time := string(linein[matchconn[8]:matchconn[9]])
			dt := dateconvert(date)
			lineoutc := fmt.Sprintf("Connection,%s,%s,%s,%s\n", ip, mac, dt, time)
			// Write output to file
			_, err = ofconn.WriteString(lineoutc)
			if err != nil {
				log.Fatalf("failed write to file: %s", err)
			}
		}

		matchdos := rxdos.FindStringSubmatchIndex(linein)
		if len(matchdos) == 12 {
			Dos++
			Linetype = "D"
			dostype := string(linein[matchdos[2]:matchdos[3]])
			ip := string(linein[matchdos[4]:matchdos[5]])
			port := string(linein[matchdos[6]:matchdos[7]])
			date := string(linein[matchdos[8]:matchdos[9]])
			time := string(linein[matchdos[10]:matchdos[11]])
			dt := dateconvert(date)
			lineoutd := fmt.Sprintf("DOS attack,%s,%s,%s,%s,%s\n", dostype, ip, port, dt, time)
			// Write output to file
			_, err = ofdos.WriteString(lineoutd)
			if err != nil {
				log.Fatalf("failed write to file: %s", err)
			}
		}

		if Linetype == "O" {
			Other++
			// Write output to file
			_, err = ofoth.WriteString(linein + "\n")
			if err != nil {
				log.Fatalf("failed write to file: %s", err)
			}
		}
	}

	fmt.Printf("Connections appended to connections.csv=%d\n", Conn)
	fmt.Printf("DOS Scans appended to dos.csv=%d\n", Dos)
	fmt.Printf("Other lines appended to other.txt=%d\n", Other)

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
