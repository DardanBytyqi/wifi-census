package main

import (
	"fmt"
	"sync"

	"go.bug.st/serial"
)

// Controller writes commands to the connected nodes' serial ports.
type Controller struct {
	mu    sync.Mutex
	ports map[string]serial.Port
}

func NewController() *Controller {
	return &Controller{ports: make(map[string]serial.Port)}
}

func (c *Controller) register(name string, port serial.Port) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ports[name] = port
}

func (c *Controller) unregister(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.ports, name)
}

// Broadcast sends cmd (newline-terminated) to every node.
func (c *Controller) Broadcast(cmd string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.ports) == 0 {
		return fmt.Errorf("no nodes connected")
	}
	var firstErr error
	for name, port := range c.ports {
		if _, err := port.Write([]byte(cmd)); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("node %s: %w", name, err)
		}
	}
	return firstErr
}
