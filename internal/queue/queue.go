package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

const ScanQueue = "bugcodeshield.scans"

type ScanJob struct {
	ScanID string `json:"scan_id"`
}

type Client struct {
	url string
}

func New(url string) *Client {
	return &Client{url: url}
}

func (c *Client) PublishScan(ctx context.Context, job ScanJob) error {
	conn, err := amqp.Dial(c.url)
	if err != nil {
		return fmt.Errorf("amqp dial: %w", err)
	}
	defer conn.Close()
	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	defer ch.Close()
	if _, err := ch.QueueDeclare(ScanQueue, true, false, false, false, nil); err != nil {
		return err
	}
	body, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return ch.PublishWithContext(ctx, "", ScanQueue, false, false, amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent,
		Body:         body,
	})
}

func (c *Client) Consume(ctx context.Context, handler func(context.Context, ScanJob) error) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := c.consumeOnce(ctx, handler); err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(3 * time.Second):
			}
		}
	}
}

func (c *Client) consumeOnce(ctx context.Context, handler func(context.Context, ScanJob) error) error {
	conn, err := amqp.Dial(c.url)
	if err != nil {
		return err
	}
	defer conn.Close()
	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	defer ch.Close()
	if err := ch.Qos(1, 0, false); err != nil {
		return err
	}
	if _, err := ch.QueueDeclare(ScanQueue, true, false, false, false, nil); err != nil {
		return err
	}
	msgs, err := ch.Consume(ScanQueue, "", false, false, false, false, nil)
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-msgs:
			if !ok {
				return fmt.Errorf("amqp channel closed")
			}
			var job ScanJob
			if err := json.Unmarshal(msg.Body, &job); err != nil {
				_ = msg.Nack(false, false)
				continue
			}
			if err := handler(ctx, job); err != nil {
				_ = msg.Nack(false, true)
				continue
			}
			_ = msg.Ack(false)
		}
	}
}
