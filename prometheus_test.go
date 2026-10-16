package main

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type asnGroup struct {
	asn   string
	count uint64
	bytes uint64
}

// Anonymous nested structs in zoneRespASN are awkward to build by hand, so go through JSON.
func newZoneRespASN(t *testing.T, groups ...asnGroup) *zoneRespASN {
	t.Helper()

	items := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		items = append(items, map[string]any{
			"count": g.count,
			"dimensions": map[string]any{
				"clientAsn":            g.asn,
				"clientASNDescription": "desc-" + g.asn,
			},
			"sum": map[string]any{"edgeResponseBytes": g.bytes},
		})
	}

	raw, err := json.Marshal(map[string]any{"zoneTag": "tag", "httpRequestsAdaptiveGroups": items})
	if err != nil {
		t.Fatal(err)
	}
	var z zoneRespASN
	if err := json.Unmarshal(raw, &z); err != nil {
		t.Fatal(err)
	}
	return &z
}

func asnLabels(zone, asn string) prometheus.Labels {
	return prometheus.Labels{"zone": zone, "account": "acc", "asn": asn, "asn_description": "desc-" + asn}
}

func TestAddASNGroupsClearsStaleSeries(t *testing.T) {
	zoneRequestASN.Reset()
	zoneBandwidthASN.Reset()

	// Scrape 1: zone-a sees ASN 100 and 200, zone-b sees ASN 300.
	addASNGroups(newZoneRespASN(t, asnGroup{"100", 10, 1000}, asnGroup{"200", 20, 2000}), "zone-a", "acc")
	addASNGroups(newZoneRespASN(t, asnGroup{"300", 30, 3000}), "zone-b", "acc")

	if got := testutil.CollectAndCount(zoneRequestASN); got != 3 {
		t.Fatalf("after scrape 1: zoneRequestASN has %d series, want 3", got)
	}

	// Scrape 2: ASN 100 disappears from zone-a, ASN 400 shows up; zone-b is not scraped.
	addASNGroups(newZoneRespASN(t, asnGroup{"200", 5, 500}, asnGroup{"400", 7, 700}), "zone-a", "acc")

	for _, vec := range []*prometheus.CounterVec{zoneRequestASN, zoneBandwidthASN} {
		if got := testutil.CollectAndCount(vec); got != 3 {
			t.Errorf("after scrape 2: %d series, want 3 (zone-a/200, zone-a/400, zone-b/300)", got)
		}
	}

	// Values must reflect the latest scrape only, not accumulate across scrapes.
	checks := []struct {
		vec   *prometheus.CounterVec
		zone  string
		asn   string
		value float64
	}{
		{zoneRequestASN, "zone-a", "200", 5},
		{zoneRequestASN, "zone-a", "400", 7},
		{zoneRequestASN, "zone-b", "300", 30},
		{zoneBandwidthASN, "zone-a", "200", 500},
		{zoneBandwidthASN, "zone-a", "400", 700},
		{zoneBandwidthASN, "zone-b", "300", 3000},
	}
	for _, c := range checks {
		if got := testutil.ToFloat64(c.vec.With(asnLabels(c.zone, c.asn))); got != c.value {
			t.Errorf("%s/%s = %v, want %v", c.zone, c.asn, got, c.value)
		}
	}
}

func TestAddASNGroupsSeriesCountStaysBounded(t *testing.T) {
	zoneRequestASN.Reset()
	zoneBandwidthASN.Reset()

	// Every scrape brings one never-seen-before ASN; the number of series must not grow with it.
	for i := 0; i < 100; i++ {
		addASNGroups(newZoneRespASN(t, asnGroup{"13335", 1, 1}, asnGroup{fmt.Sprintf("%d", 60000+i), 1, 1}), "zone-a", "acc")
	}

	for _, vec := range []*prometheus.CounterVec{zoneRequestASN, zoneBandwidthASN} {
		if got := testutil.CollectAndCount(vec); got != 2 {
			t.Errorf("after 100 scrapes: %d series, want 2", got)
		}
	}
}

func TestAddHTTPGroupsClearsStaleThreatTypes(t *testing.T) {
	zoneThreatsType.Reset()

	newZoneResp := func(threatTypes ...string) *zoneResp {
		t.Helper()
		pathing := make([]map[string]any, 0, len(threatTypes))
		for _, name := range threatTypes {
			pathing = append(pathing, map[string]any{"threatPathingName": name, "requests": 1})
		}
		raw, err := json.Marshal(map[string]any{
			"httpRequests1mGroups": []map[string]any{{"sum": map[string]any{"threatPathingMap": pathing}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		var z zoneResp
		if err := json.Unmarshal(raw, &z); err != nil {
			t.Fatal(err)
		}
		return &z
	}

	addHTTPGroups(newZoneResp("bic.ban.unknown", "hot.ban.unknown"), "zone-a", "acc")
	addHTTPGroups(newZoneResp("hot.ban.unknown"), "zone-a", "acc")

	if got := testutil.CollectAndCount(zoneThreatsType); got != 1 {
		t.Errorf("zoneThreatsType has %d series, want 1", got)
	}
}
