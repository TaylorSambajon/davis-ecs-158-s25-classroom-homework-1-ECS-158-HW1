package dns

import (
	"crypto/rand"
	"fmt"
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
	data    []RDATA // Changed type signature
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
	rootNS := NS_RECORD{"a.root-servers.net."}
	a, _ := netip.ParseAddr("198.41.0.4")
	rootIP := A_RECORD{a}
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
	//get cache index
	index := nameHash(name) % uint32(len(dnsCache))
	cacheUnit := dnsCache[index]

	/*if strings.Contains(name, "cloudflare.net") {
		fmt.Printf("CacheLookup: [%s] type %v\n", name, t)
	}*/

	//begin lookup
	//lock
	cacheUnit.lock.RLock()
	defer cacheUnit.lock.RUnlock() //unlock when done

	//fmt.Println("cacheLookup: Searching for", name, "of type", t)
	//check for name, make sure it exists
	if nameMap, exist := cacheUnit.entries[name]; exist {
		//fmt.Println("cacheLookup:", name, "found! Looking for entry...")
		//check for data and expiry
		if daEntry, exist := nameMap[t]; exist && !daEntry.isExpired() {
			//hooray we did it!
			if strings.Contains(name, "cloudflare.net") {
				fmt.Println("HIT")
			}
			return daEntry
		} else {
			//fmt.Println("Entry does not exist or is expired.")
		}
	} else {
		//fmt.Println("Unit does not exist.")
	}

	//couldn't find... sad...
	/*if strings.Contains(name, "cloudflare.net") {
		fmt.Println("MISS")
	}*/
	return nil
}

// cacheSet This will set a mapping of name/type to RDATA.
// It needs to be thread safe BUT its ok to do additional redundant setting
// if something else at the same time wants to update the data.
// If you want you can add on to the existing data if it makes your life
// easier.
func cacheSet(name string, t RTYPE, expires time.Time, data []RDATA) {
	//get unit again
	index := nameHash(name) % uint32(len(dnsCache))
	daUnit := dnsCache[index]

	//fmt.Println("cacheSet: index is", index)
	//lock it!! we're writing
	daUnit.lock.Lock()
	defer daUnit.lock.Unlock()

	//make the entry
	//fmt.Println("cacheSet: Make new entry...")
	newEntry := &dnsCacheEntry{
		expires: expires,
		data:    data,
	}

	//write entry to unit
	//make sure it aint nil
	if daUnit.entries == nil {
		daUnit.entries = make(map[string]map[RTYPE]*dnsCacheEntry)
	}

	//check for name
	if _, exist := daUnit.entries[name]; !exist {
		//make new one baybee
		daUnit.entries[name] = make(map[RTYPE]*dnsCacheEntry)
	}

	daUnit.entries[name][t] = newEntry
	if strings.Contains(name, "cloudflare.net") {
		fmt.Printf("Cache set: [%s] type %v\n", name, t)
		for _, da := range data {
			fmt.Printf(" -> data: %+v\n", da)
		}
	}

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
	//init answer array
	daAnswers := []*DNSAnswer{}

	//the lookup itself!!
	//append "." to end of name
	if !strings.HasSuffix(name, ".") || name == "" {
		name += "."
	}
	fmt.Println("QueryLookup: searching for", name, "of type", t)
	cacheEntryGet := cacheLookup(name, t)
	if cacheEntryGet != nil {
		//copy stuff
		cacheEntrydata := make([]RDATA, len(cacheEntryGet.data))
		copy(cacheEntrydata, cacheEntryGet.data)
		for _, datapiece := range cacheEntrydata {
			daAnswers = append(daAnswers, &DNSAnswer{
				RName: name, RType: t,
				RClass: 1, RData: datapiece,
			})
		}

	} else { //if the name doesn't exist...
		//get suffixes and name
		suffArr := chopName(name) //get suffixes
		bestName := getBest(suffArr)
		fmt.Println("Searching for", bestName)
		bestNS := cacheLookup(bestName, RTYPE_NS)
		for _, datapiece := range bestNS.data {
			//get da new name
			nsName := datapiece.(NS_RECORD).NS
			if !strings.HasSuffix(nsName, ".") {
				nsName += "."
			}
			fmt.Println("Current NS:", nsName)
			bnARec := cacheLookup(nsName, RTYPE_A)
			if bnARec == nil { //if does not exist, move to next one
				fmt.Println(nsName, " was empty")
				continue
			}
			if len(bnARec.data) == 0 { //if data is nil go to next one, this one is unusable
				fmt.Println("No data in", nsName)
				continue
			}
			//else we press on

			//retrieving address and establishing comm
			addr := bnARec.data[0].(A_RECORD).A //only use first one
			serverComm := getServerComm(&addr)

			//fetch request from server
			reqName := name
			if strings.HasSuffix(reqName, ".") {
				reqName = strings.TrimSuffix(reqName, ".")
			}
			request := &serverDNSRequest{
				name: reqName, qtype: t,
				response: make(chan *DNSMessage),
			}
			serverComm.requests <- request

			//wait on request, time out if too long...
			select {
			case <-time.After(3 * time.Second): //timeout
				return nil
			case respo := <-request.response:
				//begin da parse
				if respo.Header.Status != RCODE_OK {
					return nil
				}
				if respo == nil || (len(respo.Answers) == 0 && len(respo.Authorities) == 0 && len(respo.Additionals) == 0) {
					//fmt.Println("Response is nil")
					return nil
				}

				fmt.Println("Caching: ANSWERS")
				for _, ans := range respo.Answers {
					setAnsAuthAdd(ans)
				}
				fmt.Println("Caching: AUTHORITIES")
				for _, auth := range respo.Authorities {
					setAnsAuthAdd(auth)
				}
				fmt.Println("Caching: ADDITIONALS")
				for _, addit := range respo.Additionals {
					setAnsAuthAdd(addit)
				}
				if len(respo.Answers) > 0 {
					for _, ans := range respo.Answers {
						daAnswers = append(daAnswers, &ans)
					}
					return daAnswers
				}

				//check if cached
				fmt.Println("Searching request for", name)
				answer := cacheLookup(name, t)
				if answer != nil {
					answerData := make([]RDATA, len(answer.data))
					copy(answerData, answer.data)
					for _, datapiece := range answer.data {
						daAnswers = append(daAnswers, &DNSAnswer{
							RName: name, RType: t,
							RClass: 1, RData: datapiece,
						})
					}

					return daAnswers
				}

				newBestName := getBest(suffArr)
				fmt.Println("Best name:", bestName, "New best name:", newBestName)
				if newBestName == bestName {
					//we tried
					fmt.Println("No new name")
					return nil
				}
				newNS := cacheLookup(newBestName, RTYPE_NS)
				if newNS == nil {
					fmt.Println("No NS records for", newNS)
					return nil
				}
				return QueryLookup(name, t)

			} //end select case

		} //end searching for NS

		//if we made it here, we don't have a decent A record from the NS.
		fmt.Println("No A_Record for this NS")
		return nil

	} //end iterative lookup

	return daAnswers
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
	//thread safe(?)
	index := serverHash(addr) % uint32(len(serverCommCache))
	commUnit := serverCommCache[index]

	//lock while checking. uhhh i wasn't told to but
	//just in case hoho
	commUnit.lock.RLock()

	//does it exist?
	c, exist := commUnit.entries[*addr]
	commUnit.lock.RUnlock()

	if exist {
		return c
	}

	//unlock then establish if no
	c = establishServerComm(addr)
	return c
}

// This needs to be safe:  It needs to acquire a write lock and first
// make sure that there isn't another write that happened in the meantime.
// If there isn't it should invoke commConnect to get the new server manager
// to be set/returned.
func establishServerComm(addr *netip.Addr) *serverCommManager {
	//needs a write lock lol let's get that first
	index := serverHash(addr) % uint32(len(serverCommCache))
	commUnit := serverCommCache[index]

	commUnit.lock.Lock()
	defer commUnit.lock.Unlock()

	//lock acquired
	//fmt.Println("establishServerComm: commConnect to", addr)
	//check if exists
	if commExist, exist := commUnit.entries[*addr]; exist {
		return commExist
	} else {
		commMan := commConnect(addr)
		if commMan != nil {

			//set new communication manager
			if commUnit.entries == nil {
				//fmt.Println("New map made for", addr)
				commUnit.entries = make(map[netip.Addr]*serverCommManager)
			}
			commUnit.entries[*addr] = commMan
			return commMan
		} //end nil comm if
	} //end exist if

	//fmt.Println("establishServerComm: could not find", addr)
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

// helper functions go here
// check if expired
func (c *dnsCacheEntry) isExpired() bool {
	return time.Now().After(c.expires)
}

// chop up to "." in name
// be searched!
func chopName(name string) []string {
	var chopped []string
	pieces := strings.Split(name, ".")

	//get suffArray
	for i := range pieces {
		suff := strings.Join(pieces[i:], ".")
		//fmt.Println(suff)
		if suff != "" {
			chopped = append(chopped, suff)
		}
		if !strings.HasSuffix(suff, ".") {
			//fmt.Println("we're appending! for some reason.")
			chopped = append(chopped, ".")
		}
	}
	//fmt.Println("Returning suffix array:", chopped)
	return chopped //put it back
}

// traverse suffix array to get better NS
func getBest(suffArr []string) string {
	var currBest string
	//fmt.Println(suffArr)
	bestName := ""
	for _, x := range suffArr {
		//fmt.Println("Looking for", x)
		if cacheLookup(x, RTYPE_NS) != nil {
			currBest = x
			if len(currBest) > len(bestName) {
				bestName = currBest
			}
		}
	}
	return bestName
}

// makes setting the cache easier in QueryLookup
func setAnsAuthAdd(entry DNSAnswer) {
	name := entry.RName

	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	fmt.Println("Info for current cache... Name:", name, "Type:", entry.RType, "Class:", entry.RClass, "Data:", entry.RData)

	//caching found entry
	//exist := cacheLookup(name, entry.RType)

	if strings.Contains(name, "cloudflare.net") {
		fmt.Printf("Set auth/add: [%s] type %v\n", entry.RName, entry.RType)
	}
	cacheSet(name, entry.RType, time.Now().Add(time.Hour*24*365), []RDATA{entry.RData})

}
