package reflplan

import (
	"reflect"
	"sync"
	"testing"
)

type leaf struct {
	A string
	B int
	C struct{ X, Y int }
}
type selfLeaf struct {
	Name string
	Next *selfLeaf
}
type withIface struct {
	Name string
	E    any
	L    leaf
	S    []leaf
	M    map[string]any
	P    *selfLeaf
	hid  any
}
type cycA struct {
	B *cycB
	N int
}
type cycB struct {
	A   []cycA
	Val any
}

type Embedded struct{ Value any }

func TestPlanContainers(t *testing.T) {
	for _, value := range []any{map[string]any{}, []any{}, [0]any{}, (*any)(nil)} {
		typ := reflect.TypeOf(value)
		p := Of(typ)
		if !p.Reach || p.Elem == nil || !p.Elem.Reach || p.Elem.Type != typ.Elem() {
			t.Errorf("%v: incomplete container plan: %+v", typ, p)
		}
	}
	// Only map values carry rewrite slots; interface keys do not reach.
	for _, value := range []any{map[any]int{}, []leaf{}, [0]leaf{}, (*selfLeaf)(nil)} {
		typ := reflect.TypeOf(value)
		p := Of(typ)
		if p.Reach || p.Elem == nil || p.Elem.Reach || p.Elem.Type != typ.Elem() {
			t.Errorf("%v: invalid leaf container plan: %+v", typ, p)
		}
	}
	typ := reflect.TypeOf(struct {
		Before int
		Embedded
		After string
	}{})
	p := Of(typ)
	if !p.Reach || !reflect.DeepEqual(indices(p), []int{1}) || !reflect.DeepEqual(indices(p.Fields[0].Plan), []int{0}) {
		t.Fatalf("embedded plan = %+v", p)
	}
	if Of(reflect.TypeOf(struct{ hidden any }{})).Reach {
		t.Fatal("unexported interface field must not reach")
	}
}

func indices(p *Plan) []int {
	var out []int
	for _, f := range p.Fields {
		out = append(out, f.Index)
	}
	return out
}

func TestPlans(t *testing.T) {
	if Of(reflect.TypeOf(leaf{})).Reach || Of(reflect.TypeOf(selfLeaf{})).Reach {
		t.Fatal("interface-free types must not reach")
	}
	p := Of(reflect.TypeOf(withIface{}))
	if !p.Reach || !reflect.DeepEqual(indices(p), []int{1, 4}) {
		t.Fatalf("withIface fields = %v", indices(p))
	}
	a := Of(reflect.TypeOf(&cycA{}))
	if !a.Reach || !a.Elem.Reach || !reflect.DeepEqual(indices(a.Elem), []int{0}) {
		t.Fatalf("cycA = %+v", a.Elem)
	}
	b := a.Elem.Fields[0].Plan
	if b.Elem == nil || !b.Reach || !reflect.DeepEqual(indices(b.Elem), []int{0, 1}) {
		t.Fatalf("cycB = %+v", b)
	}
	back := b.Elem.Fields[0].Plan
	if back.Elem == nil || back.Elem.Type != reflect.TypeOf(cycA{}) || !back.Reach {
		t.Fatalf("cycle back edge = %+v", back)
	}
}

func TestConcurrentBuild(t *testing.T) {
	// Unique types exercise cold-cache publication even after TestPlans.
	type concurrentA struct {
		Next  *concurrentA
		Value any
	}
	typ := reflect.TypeOf(struct{ A []map[int]*concurrentA }{})
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 32 {
				p := Of(typ)
				if !p.Reach || !reflect.DeepEqual(indices(p), []int{0}) {
					t.Errorf("incomplete published plan: %+v", p)
					return
				}
				elem := p.Fields[0].Plan
				for _, kind := range []reflect.Kind{reflect.Slice, reflect.Map, reflect.Pointer} {
					if elem.Kind != kind || elem.Elem == nil || !elem.Reach {
						t.Errorf("incomplete container plan: %+v", elem)
						return
					}
					elem = elem.Elem
				}
				if elem.Kind != reflect.Struct || !elem.Reach || !reflect.DeepEqual(indices(elem), []int{0, 1}) {
					t.Errorf("incomplete cycle plan: %+v", elem)
				}
			}
		}()
	}
	close(start)
	wg.Wait()
}
