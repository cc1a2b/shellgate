package acl

import (
	"fmt"
	"net"

	"github.com/oschwald/maxminddb-golang"
)

// GeoInfo holds geolocation information for an IP address.
type GeoInfo struct {
	CountryCode string
	CountryName string
	City        string
}

// GeoIPResolver wraps a MaxMind GeoLite2 database for IP geolocation.
type GeoIPResolver struct {
	db *maxminddb.Reader
}

// maxmindRecord maps the MaxMind database record structure.
type maxmindRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
}

// NewGeoIPResolver opens a MaxMind .mmdb file and returns a resolver.
func NewGeoIPResolver(dbPath string) (*GeoIPResolver, error) {
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open maxmind db: %w", err)
	}
	return &GeoIPResolver{db: db}, nil
}

// Lookup returns geolocation information for the given IP.
func (g *GeoIPResolver) Lookup(ip net.IP) (*GeoInfo, error) {
	var record maxmindRecord
	err := g.db.Lookup(ip, &record)
	if err != nil {
		return nil, fmt.Errorf("geoip lookup: %w", err)
	}

	info := &GeoInfo{
		CountryCode: record.Country.ISOCode,
	}
	if name, ok := record.Country.Names["en"]; ok {
		info.CountryName = name
	}
	if name, ok := record.City.Names["en"]; ok {
		info.City = name
	}

	return info, nil
}

// Close closes the database reader.
func (g *GeoIPResolver) Close() {
	if g.db != nil {
		g.db.Close()
	}
}
