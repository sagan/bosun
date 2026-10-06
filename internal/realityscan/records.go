package realityscan

import "net"

// The tested Xray 26.3.27 and older REALITY implementations use this
// bound. This is conservative screening, not a complete REALITY handshake:
// the upstream parser also bounds accumulated records, and a different
// ClientHello or CDN edge can yield a different server flight.
const targetRecordLimit = 8192

// recordConn observes wire lengths, including headers, encryption overhead
// and stapled certificate extensions. Summing certificate DER bytes would
// miss the OCSP data responsible for XTLS/Xray-core#6356. Keep only a header
// and counters; never retain certificates, application data or TLS secrets.
type recordConn struct {
	net.Conn
	header    [5]byte
	headerN   int
	remaining int
	maxRecord int
}

func (c *recordConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.observe(p[:n])
	return n, err
}

func (c *recordConn) observe(p []byte) {
	for len(p) > 0 {
		if c.remaining > 0 {
			n := min(len(p), c.remaining)
			c.remaining -= n
			p = p[n:]
			continue
		}
		n := copy(c.header[c.headerN:], p)
		c.headerN += n
		p = p[n:]
		if c.headerN < len(c.header) {
			continue
		}
		c.headerN = 0
		c.remaining = int(c.header[3])<<8 | int(c.header[4])
		// crypto/tls validates the full record. Ignore non-TLS response
		// headers here rather than labelling an HTTP error a large record.
		if c.header[0] >= 20 && c.header[0] <= 23 && c.header[1] == 3 {
			c.maxRecord = max(c.maxRecord, len(c.header)+c.remaining)
		}
	}
}
