package dns

import (
	"crypto/rand"
	"hash/fnv"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// dnsCacheEntry An actual cache entry, it has both an
// expires time and the rdata itself.
type dnsCacheEntry struct {
	expires time.Time
	data    []*RDATA
}

// dnsCacheUnit This is our basic unit of locking within
// the cache itself.  It consists of both a RWMutex and
// a map between the name/rtype and the cache entry.
// The name should be all lower case when looking/storing
// in this cache.
type dnsCacheUnit struct {
	lock sync.RWMutex
	// An entry itself is a 2-level map, the first being the name
	// (with the trailing '.', in all lower case)
	// and the second being the
	// cache entry itself.
	entries map[string]map[RTYPE]*dnsCacheEntry
}

var dnsCache []*dnsCacheUnit
var seed []byte

// This function needs to be called at the start
// to initialize all the cache entries.  It is
// public because it is part of the setup process
func InitCache(n uint) {
	dnsCache = make([]*dnsCacheUnit, n)
	for i := uint(0); i < n; i++ {
		dnsCache[i] = &dnsCacheUnit{}
	}
	// The error does NOT need to be handled,
	// as rand.Read will ALWAYS fail if it doesn't work
	// with a panic, but just because this is there to
	// suppress a compiler/IDE warning
	_, _ = rand.Read(seed)
	initRoot()
}

func initRoot() {
	rootNS := &NS_RECORD{"a.root-servers.net."}
	a, _ := netip.ParseAddr("198.41.0.4")
	rootIP := &A_RECORD{a}
	cacheSet(".", RTYPE_NS,
		time.Now().Add(time.Hour*24*365),
		[]RDATA{rootNS})

	cacheSet("a.root-servers.net.",
		RTYPE_A,
		time.Now().Add(time.Hour*24*365),
		[]RDATA{rootIP})

}

// cacheLookup This will look up the entry in the cache for
// the given name and rtype.  If the name doesn't exist, the rtype
// doesn't exist, or the record is expired it should return nil
func cacheLookup(name string, t RTYPE) *dnsCacheEntry {
	// TODO: You need to implement this and make sure this is thread safe.
	return nil
}

// cacheSet This will set a mapping of name/type to RDATA.
// It needs to be thread safe BUT its ok to do additional redundant setting
// if something else at the same time wants to update the data.
func cacheSet(name string, t RTYPE, expires time.Time, data []RDATA) {
	// TODO: You need to implement this to make sure it is thread safe
	return
}

// nameHash This is a basic hash function for strings.
// Note this is deliberately nondeterministic between
// runs:  The seed is randomly created.  This is
// to both prevent an attack ("algorithmic complexity attack"
// where an attacker creates a deliberate hot-spot in the cache)
// and to ensure that there is a lot of randomization between
// runs.
func nameHash(name string) uint32 {
	l := strings.ToLower(name)
	h := fnv.New32a()
	_, _ = h.Write([]byte(l))
	_, _ = h.Write(seed)
	return h.Sum32()
}

// serverHash This is the same thing but for server
// addressses using the netip.Addr structure
func serverHash(addr *netip.Addr) uint32 {
	l := addr.String()
	h := fnv.New32a()
	_, _ = h.Write([]byte(l))
	_, _ = h.Write(seed)
	return h.Sum32()
}

// And this is the heart of the lookup:  Every query executed will be
// in its own coroutine.  It should check the cache for the name and, if present
// & valid, return it.  If not it will need to do iterative lookups
// by first looking up the NS record for the domain (if present) and querying that
//
// If the value is a CNAME it should also follow the CNAME and return that as part of
// the answer.  For now we will only deal with RTYPE_A records
func QueryLookup(name string, t RTYPE) []*DNSAnswer {
	// TODO You need to implement this
	return nil
}

// The protocol for generating a request to a server:
// We send a name and a string for the question, and
// get a response back on the DNSMessage channel.  This
// allows many coroutines to access the underlying server
// communication.

// Critically, however, a server may simply not respond.  In this
// case the process will need to instead have a timeout and go on
// to try another server.
type serverDNSRequest struct {
	name     string
	qtype    RTYPE
	response chan *DNSMessage
}

type serverCommManager struct {
	remote   *netip.Addr
	requests chan *serverDNSRequest
}

type serverCommUnit struct {
	lock sync.RWMutex
	// An entry itself is a 1 level map based
	// on the remote server address
	// Note that we need to be address type not
	// pointer address type due to how things work
	// with maps
	entries map[netip.Addr]*serverCommManager
}

var serverCommCache []*serverCommUnit

// And this inits the cache for server communication.
func InitServerComm(n uint) {
	serverCommCache = make([]*serverCommUnit, n)
	for i := uint(0); i < n; i++ {
		serverCommCache[i] = &serverCommUnit{}
	}
}

func getServerComm(addr *netip.Addr) *serverCommManager {
	// TODO you need to implement this
	return nil
}

// This needs to be safe:  It needs to acquire a write lock and first
// make sure that there isn't another write that happened in the meantime.
// If there isn't it should invoke commConnect to get the new server manager
// to be set/returned.
func establishServerComm(addr *netip.Addr) *serverCommManager {
	// TODO you need to implement this.
	return nil
}

// commConnect We have our function to create an interface
// to the server manager be a variable rather than a declared
// function to enable testing:  The test infrastructure will use
// a mock version of the function to establish a connection.  If we were
// building a complete server we wolud have this function
// instead do the actual connections.
// This needs to be exposed for now.

// For now we only accept IPv4 (A) record based addresses.
var commConnect func(*netip.Addr) *serverCommManager
