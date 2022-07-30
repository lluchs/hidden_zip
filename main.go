// Copyright 2022 Lukas Werling
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const fileHeaderSignature = 0x04034b50

// scanReader reads from r until it finds sep, returning a slice of read data after sep.
func scanReader(r io.Reader, sep []byte) ([]byte, error) {
	start := 0
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf[start:])
		if err != nil {
			return nil, err
		}
		n += start
		if idx := bytes.Index(buf[:n], sep); idx != -1 {
			//fmt.Printf("idx=%d, n=%d len(sep)=%d\n", idx, n, len(sep))
			return buf[idx+len(sep) : n], nil
		}
		// Make sure we don't miss s at the read boundary.
		start = len(sep) - 1
		copy(buf[:start], buf[n-start:])
	}
}

type FileHeader = struct {
	version, flags, compression, mtime, mdate, namelen, extralen uint16
	crc32, csize, size                                           uint32
	name                                                         string
	extra                                                        []byte
}

func nextFileHeader(r io.ReadSeeker) (*FileHeader, error) {
	sep := new(bytes.Buffer)
	err := binary.Write(sep, binary.LittleEndian, uint32(fileHeaderSignature))
	if err != nil {
		fmt.Println("binary.Write failed:", err)
		return nil, err
	}
	for {
		rest, err := scanReader(r, sep.Bytes())
		if err != nil {
			return nil, err
		}
		// assume maximum file and extra length of 255
		headersize := 30 + 255
		if len(rest) < headersize {
			rest = append(rest, make([]byte, headersize)...)
			n, err := r.Read(rest[len(rest)-headersize:])
			if err != nil {
				return nil, err
			}
			rest = rest[len(rest)-headersize : len(rest)-headersize+n]
		}
		buf := bytes.NewBuffer(rest)
		var h FileHeader
		binary.Read(buf, binary.LittleEndian, &h.version)
		binary.Read(buf, binary.LittleEndian, &h.flags)
		binary.Read(buf, binary.LittleEndian, &h.compression)
		binary.Read(buf, binary.LittleEndian, &h.mtime)
		binary.Read(buf, binary.LittleEndian, &h.mdate)
		binary.Read(buf, binary.LittleEndian, &h.crc32)
		binary.Read(buf, binary.LittleEndian, &h.csize)
		binary.Read(buf, binary.LittleEndian, &h.size)
		binary.Read(buf, binary.LittleEndian, &h.namelen)
		binary.Read(buf, binary.LittleEndian, &h.extralen)
		//fmt.Printf("version=%d flags=%x compression=%d mtime=%d mdate=%d crc32=%x csize=%d size=%d namelen=%d extralen=%d\n",
		//h.version, h.flags, h.compression, h.mtime, h.mdate, h.crc32, h.csize, h.size, h.namelen, h.extralen)

		if h.namelen > 255 || h.extralen > 255 || h.namelen+h.extralen > 255 {
			_, err = r.Seek(-int64(len(rest)), io.SeekCurrent)
			continue
		}
		h.name = string(rest[26 : 26+h.namelen])
		h.extra = append(h.extra, rest[26+h.namelen:26+h.namelen+h.extralen]...)

		// Don't skip over file contents to find nested zip entries.
		//_, err = r.Seek(-int64(len(rest))+26+int64(h.namelen)+int64(h.extralen)+int64(h.size), io.SeekCurrent)
		_, err = r.Seek(-int64(len(rest))+26+int64(h.namelen)+int64(h.extralen), io.SeekCurrent)
		if err != nil {
			return nil, err
		}

		return &h, nil
	}
}

func searchFileHeaders(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	for {
		header, err := nextFileHeader(f)
		if err != nil {
			return err
		}
		pos, err := f.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}
		fmt.Printf("%s at %d len %d\n", header.name, pos, header.size)
	}

}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <file.zip>\n", os.Args[0])
		fmt.Println("Find hidden files in a Zip archive by looking for local file headers.")
	}
	err := searchFileHeaders(os.Args[1])
	if err != nil {
		fmt.Println(err)
	}
}
