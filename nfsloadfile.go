/* 
   dbench version 3

   Copyright (C) Raymond Barbiero 2012
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type entry struct {
	pattern string
	once    sync.Once
	reg     *regexp.Regexp
}

func (e *entry) match(x string) bool {
	e.once.Do(func() {
		e.reg = regexp.MustCompile(e.pattern)
	})
	return e.reg.MatchString(x)
}

func (e *entry) extract_field(x string) string {
	e.once.Do(func() {
		e.reg = regexp.MustCompile(e.pattern)
	})
	matches := e.reg.FindStringSubmatch(x)
	result := ""
	if len(matches) == 2 {
		result = matches[1]
	} else {
	}
	return result
}

func getLine(last []byte, data []byte) (line []byte, rest []byte) {
	i := bytes.Index(data, []byte{'\n'})
	var j int
	if i < 0 {
		line = nil
		rest = data
	} else {
		j = i + 1
		if i > 0 && data[i-1] == '\r' {
			i--
		}
		line = bytes.TrimRight(data[0:i], " \t")
		rest = data[j:]
	}
	return append(last, line...), rest
}

func do_readdirplus(db map[string]string, timestamp string,
	xid string, msgtyp string, fullname string,
	cookie string, status string) {
	if msgtyp != "1" {
		var buf bytes.Buffer
		fmt.Fprint(&buf, timestamp, " READDIRPLUS3 ", `"`+fullname+`"`, " "+cookie)
		db[xid] = string(buf.Bytes())
	} else {
		if command, ok := db[xid]; ok {
			fmt.Println(command, status)
		}
	}
}

func do_write(db map[string]string, timestamp string,
	xid string, msgtyp string, fullname string,
	offset string, count string, stable string, status string) {
	if msgtyp != "1" {
		var buf bytes.Buffer
		fmt.Fprint(&buf, timestamp, " WRITE3 ", `"`+fullname+`"`, " "+offset, " "+count, " "+stable)
		db[xid] = string(buf.Bytes())
	} else {
		if command, ok := db[xid]; ok {
			fmt.Println(command, status)
		}
	}
}

func do_read(db map[string]string, timestamp string,
	xid string, msgtyp string, fullname string,
	offset string, count string, status string) {
	if msgtyp != "1" {
		var buf bytes.Buffer
		fmt.Fprint(&buf, timestamp, " READ3 ", `"`+fullname+`"`, " "+offset, " "+count)
		db[xid] = string(buf.Bytes())
	} else {
		if command, ok := db[xid]; ok {
			fmt.Println(command, status)
		}
	}
}

func do_create(db map[string]string, timestamp string,
	xid string, msgtyp string, fullname string,
	name string, mode string, status string) {
	if msgtyp != "1" {
		var buf bytes.Buffer
		fmt.Fprint(&buf, timestamp, " CREATE3 ", `"`+fullname+`/`+name+`"`, " "+mode)
		db[xid] = string(buf.Bytes())
	} else {
		if command, ok := db[xid]; ok {
			fmt.Println(command, status)
		}
	}
}

func do_lookup(db map[string]string, timestamp string,
	xid string, msgtyp string, fullname string,
	name string, status string) {
	if msgtyp != "1" {
		var buf bytes.Buffer
		fmt.Fprint(&buf, timestamp, " LOOKUP3 ", `"`+fullname+`/`+name+`"`)
		db[xid] = string(buf.Bytes())
	} else {
		if command, ok := db[xid]; ok {
			fmt.Println(command, status)
		}
	}
}

func do_getattr(db map[string]string, timestamp string,
	xid string, msgtyp string, fullname string,
	status string) {
	if msgtyp != "1" {
		var buf bytes.Buffer
		fmt.Fprint(&buf, timestamp, " GETATTR3 ", `"`+fullname+`"`)
		db[xid] = string(buf.Bytes())
	} else {
		if command, ok := db[xid]; ok {
			fmt.Println(command, status)
		}
	}
}

func do_fsinfo(db map[string]string, timestamp string,
	xid string, msgtyp string, status string) {
	if msgtyp != "1" {
		var buf bytes.Buffer
		fmt.Fprint(&buf, timestamp, " FSINFO3")
		db[xid] = string(buf.Bytes())
	} else {
		if command, ok := db[xid]; ok {
			fmt.Println(command, status)
		}
	}
}

func do_access(db map[string]string, timestamp string,
	xid string, msgtyp string, fullname string,
	status string) {
	if msgtyp != "1" {
		var buf bytes.Buffer
		fmt.Fprint(&buf, timestamp, " ACCESS3 ", `"`+fullname+`"`, " 0 0")
		db[xid] = string(buf.Bytes())
	} else {
		if command, ok := db[xid]; ok {
			fmt.Println(command, status)
		}
	}
}

func main() {
	cmd := exec.Command("tshark", "-n", "-r", os.Args[1], "-R nfs",
		"-o", "nfs.file_name_snooping:TRUE",
		"-o", "nfs.file_full_name_snooping:TRUE",
		"-o", "nfs.fhandle_find_both_reqrep:TRUE",
		"-z", "proto,colinfo,rpc.xid,rpc.xid",
		"-z", "proto,colinfo,rpc.msgtyp,rpc.msgtyp",
		"-z", "proto,colinfo,nfs.nfsstat3,nfs.nfsstat3",
		"-z", "proto,colinfo,nfs.name,nfs.name",
		"-z", "proto,colinfo,nfs.full_name,nfs.full_name",
		"-z", "proto,colinfo,nfs.createmode,nfs.createmode",
		"-z", "proto,colinfo,nfs.offset3,nfs.offset3",
		"-z", "proto,colinfo,nfs.count3,nfs.count3",
		"-z", "proto,colinfo,nfs.cookie3,nfs.cookie3",
		"-z", "proto,colinfo,nfs.write.stable,nfs.write.stable",
		"-z", "proto,colinfo,nfs.procedure_v3,nfs.procedure_v3",
		"-z", "proto,colinfo,frame.time_relative,frame.time_relative")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}

	ch := make(chan string)
	quit := make(chan bool)
	go func() {
		s := bufio.NewReader(stdout)
		for {
			line, err := s.ReadString('\n')
			if err == io.EOF && len(line) == 0 {
				break
			}
			if err == io.EOF {
				err := fmt.Errorf("Last line not terminated: %q", line)
				panic(err)
			}
			if err != nil {
				panic(err)
			}
			line = line[:len(line)-1] // drop the '\n'
			if line[len(line)-1] == '\r' {
				line = line[:len(line)-1] // drop the '\r'
			}

			ch <- line
		}
		close(ch)
	}()

	timestamp_capture := &entry{pattern: "^.*frame.time_relative == ([^ ]+)"}
	xid_capture := &entry{pattern: "^.*rpc.xid == ([^ ]+)"}
	msgtyp_capture := &entry{pattern: "^.*rpc.msgtyp == ([^ ]+)"}
	status_capture := &entry{pattern: "^.*nfs.nfsstat3 == ([^ ]+)"}
	name_capture := &entry{pattern: "^.*nfs.name == \"([^\"]+)\""}
	fullname_capture := &entry{pattern: "^.*nfs.full_name == \"([^\"]+)\""}
	cookie_capture := &entry{pattern: "^.*nfs.cookie3 == ([^ ]+)"}
	offset_capture := &entry{pattern: "^.*nfs.offset3 == ([^ ]+)"}
	count_capture := &entry{pattern: "^.*nfs.count3 == ([^ ]+)"}
	stable_capture := &entry{pattern: "^.*nfs.write.stable == ([^ ]+)"}
	mode_capture := &entry{pattern: "^.*nfs.createmode == ([^ ]+)"}
	readdirplus := &entry{pattern: "^.*nfs.procedure_v3 == 17"}
	read := &entry{pattern: "^.*nfs.procedure_v3 == 6"}
	write := &entry{pattern: "^.*nfs.procedure_v3 == 7"}
	create := &entry{pattern: "^.*nfs.procedure_v3 == 8"}
	lookup := &entry{pattern: "^.*nfs.procedure_v3 == 3"}
	fsinfo := &entry{pattern: "^.*nfs.procedure_v3 == 19"}
	getattr := &entry{pattern: "^.*nfs.procedure_v3 == 1 "}
	access := &entry{pattern: "^.*nfs.procedure_v3 == 4"}
	db := make(map[string]string)
loop:
	for {
		select {
		case packet, ok := <-ch:
			if !ok {
				break loop
			}
			timestamp := timestamp_capture.extract_field(packet)
			switch {
			case readdirplus.match(packet):
				xid := xid_capture.extract_field(packet)
				msgtyp := msgtyp_capture.extract_field(packet)

				status := ""
				status_str := status_capture.extract_field(packet)
				if status_str != "" {
					status_int, err := strconv.Atoi(status_str)
					if err != nil {
						status = ""
					} else {
						var status_field bytes.Buffer
						fmt.Fprintf(&status_field, "0x%08x", status_int)
						status = string(status_field.Bytes())
					}
				}

				fullname := fullname_capture.extract_field(packet)
				cookie := cookie_capture.extract_field(packet)

				do_readdirplus(db, timestamp, xid, msgtyp, fullname, cookie, status)
			case read.match(packet):
				xid := xid_capture.extract_field(packet)
				msgtyp := msgtyp_capture.extract_field(packet)

				status := ""
				status_str := status_capture.extract_field(packet)
				if status_str != "" {
					status_int, err := strconv.Atoi(status_str)
					if err != nil {
						status = ""
					} else {
						var status_field bytes.Buffer
						fmt.Fprintf(&status_field, "0x%08x", status_int)
						status = string(status_field.Bytes())
					}
				}

				fullname := fullname_capture.extract_field(packet)
				offset := offset_capture.extract_field(packet)
				count := count_capture.extract_field(packet)

				do_read(db, timestamp, xid, msgtyp, fullname, offset, count, status)
			case write.match(packet):
				xid := xid_capture.extract_field(packet)
				msgtyp := msgtyp_capture.extract_field(packet)

				status := ""
				status_str := status_capture.extract_field(packet)
				if status_str != "" {
					status_int, err := strconv.Atoi(status_str)
					if err != nil {
						status = ""
					} else {
						var status_field bytes.Buffer
						fmt.Fprintf(&status_field, "0x%08x", status_int)
						status = string(status_field.Bytes())
					}
				}

				fullname := fullname_capture.extract_field(packet)
				offset := offset_capture.extract_field(packet)
				count := count_capture.extract_field(packet)
				stable := stable_capture.extract_field(packet)

				do_write(db, timestamp, xid, msgtyp, fullname, offset, count, stable, status)
			case create.match(packet):
				xid := xid_capture.extract_field(packet)
				msgtyp := msgtyp_capture.extract_field(packet)

				status := ""
				status_str := status_capture.extract_field(packet)
				if status_str != "" {
					status_int, err := strconv.Atoi(status_str)
					if err != nil {
						status = ""
					} else {
						var status_field bytes.Buffer
						fmt.Fprintf(&status_field, "0x%08x", status_int)
						status = string(status_field.Bytes())
					}
				}

				name := name_capture.extract_field(packet)
				fullname := fullname_capture.extract_field(packet)
				mode := mode_capture.extract_field(packet)

				do_create(db, timestamp, xid, msgtyp, fullname, name, mode, status)
			case lookup.match(packet):
				xid := xid_capture.extract_field(packet)
				msgtyp := msgtyp_capture.extract_field(packet)

				status := ""
				status_str := status_capture.extract_field(packet)
				if status_str != "" {
					status_int, err := strconv.Atoi(status_str)
					if err != nil {
						status = ""
					} else {
						var status_field bytes.Buffer
						fmt.Fprintf(&status_field, "0x%08x", status_int)
						status = string(status_field.Bytes())
					}
				}

				name := name_capture.extract_field(packet)
				fullname := fullname_capture.extract_field(packet)

				do_lookup(db, timestamp, xid, msgtyp, fullname, name, status)
			case fsinfo.match(packet):
				xid := xid_capture.extract_field(packet)
				msgtyp := msgtyp_capture.extract_field(packet)

				status := ""
				status_str := status_capture.extract_field(packet)
				if status_str != "" {
					status_int, err := strconv.Atoi(status_str)
					if err != nil {
						status = ""
					} else {
						var status_field bytes.Buffer
						fmt.Fprintf(&status_field, "0x%08x", status_int)
						status = string(status_field.Bytes())
					}
				}

				do_fsinfo(db, timestamp, xid, msgtyp, status)
			case getattr.match(packet):
				xid := xid_capture.extract_field(packet)
				msgtyp := msgtyp_capture.extract_field(packet)

				status := ""
				status_str := status_capture.extract_field(packet)
				if status_str != "" {
					status_int, err := strconv.Atoi(status_str)
					if err != nil {
						status = ""
					} else {
						var status_field bytes.Buffer
						fmt.Fprintf(&status_field, "0x%08x", status_int)
						status = string(status_field.Bytes())
					}
				}

				fullname := fullname_capture.extract_field(packet)

				do_getattr(db, timestamp, xid, msgtyp, fullname, status)
			case access.match(packet):
				xid := xid_capture.extract_field(packet)
				msgtyp := msgtyp_capture.extract_field(packet)

				status := ""
				status_str := status_capture.extract_field(packet)
				if status_str != "" {
					status_int, err := strconv.Atoi(status_str)
					if err != nil {
						status = ""
					} else {
						var status_field bytes.Buffer
						fmt.Fprintf(&status_field, "0x%08x", status_int)
						status = string(status_field.Bytes())
					}
				}

				fullname := fullname_capture.extract_field(packet)

				do_access(db, timestamp, xid, msgtyp, fullname, status)
			//case mkdir.match(packet):
			//case remove.match(packet):
			//case rename.match(packet):
			//case link.match(packet):
			//case deltree.match(packet):
			//case commit.match(packet):
			//case rmdir.match(packet):
			//case fsstat.match(packet):
			//case symlink.match(packet):
			default:
				fmt.Println("XXX unknown packet", strings.TrimLeft(packet, " "))
			}
		case <-quit:
			cmd.Process.Kill()
		}
	}
}
