package http

import "strings"

type Route struct {
	Pattern string
	Method  string
	Handler HandlerFunc
}

type trieNode struct {
	children map[string]*trieNode
	param    *trieNode
	paramKey string
	wildcard *trieNode
	handlers map[string]*Route
}

type Router struct {
	root *trieNode
}

func NewRouter() *Router {
	return &Router{
		root: &trieNode{
			children: make(map[string]*trieNode),
			handlers: make(map[string]*Route),
		},
	}
}

func (r *Router) Add(method, pattern string, handler HandlerFunc) {
	segments := splitPath(pattern)
	node := r.root

	for _, seg := range segments {
		switch {
		case seg == "*":
			if node.wildcard == nil {
				node.wildcard = &trieNode{
					children: make(map[string]*trieNode),
					handlers: make(map[string]*Route),
				}
			}
			node = node.wildcard
		case strings.HasPrefix(seg, ":"):
			if node.param == nil {
				node.param = &trieNode{
					children: make(map[string]*trieNode),
					handlers: make(map[string]*Route),
				}
			}
			node.paramKey = seg[1:]
			node = node.param
		default:
			child, ok := node.children[seg]
			if !ok {
				child = &trieNode{
					children: make(map[string]*trieNode),
					handlers: make(map[string]*Route),
				}
				node.children[seg] = child
			}
			node = child
		}
	}

	node.handlers[method] = &Route{
		Pattern: pattern,
		Method:  method,
		Handler: handler,
	}
}

func (r *Router) Match(method, path string) (*Route, map[string]string) {
	segments := splitPath(path)
	params := make(map[string]string)

	route := r.match(r.root, method, segments, 0, params)
	if route == nil {
		return nil, nil
	}
	return route, params
}

func (r *Router) match(node *trieNode, method string, segments []string, i int, params map[string]string) *Route {
	if i == len(segments) {
		if route, ok := node.handlers[method]; ok {
			return route
		}
		return nil
	}

	seg := segments[i]

	if child, ok := node.children[seg]; ok {
		if route := r.match(child, method, segments, i+1, params); route != nil {
			return route
		}
	}

	if node.param != nil {
		prev, hadPrev := params[node.paramKey]
		params[node.paramKey] = seg
		if route := r.match(node.param, method, segments, i+1, params); route != nil {
			return route
		}
		if hadPrev {
			params[node.paramKey] = prev
		} else {
			delete(params, node.paramKey)
		}
	}

	if node.wildcard != nil {
		remaining := strings.Join(segments[i:], "/")
		prev, hadPrev := params["*"]
		params["*"] = remaining
		if route, ok := node.wildcard.handlers[method]; ok {
			return route
		}
		if hadPrev {
			params["*"] = prev
		} else {
			delete(params, "*")
		}
	}

	return nil
}

func (r *Router) AllowedMethods(path string) []string {
	segments := splitPath(path)
	params := make(map[string]string)
	node := r.findNode(r.root, segments, 0, params)
	if node == nil {
		return nil
	}
	methods := make([]string, 0, len(node.handlers))
	for m := range node.handlers {
		methods = append(methods, m)
	}
	return methods
}

func (r *Router) findNode(node *trieNode, segments []string, i int, params map[string]string) *trieNode {
	if i == len(segments) {
		if len(node.handlers) > 0 {
			return node
		}
		return nil
	}

	seg := segments[i]

	if child, ok := node.children[seg]; ok {
		if found := r.findNode(child, segments, i+1, params); found != nil {
			return found
		}
	}

	if node.param != nil {
		if found := r.findNode(node.param, segments, i+1, params); found != nil {
			return found
		}
	}

	if node.wildcard != nil && len(node.wildcard.handlers) > 0 {
		return node.wildcard
	}

	return nil
}

func splitPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	return strings.Split(path, "/")
}
