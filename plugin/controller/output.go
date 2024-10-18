package controller

import (
	"context"
	"fmt"
	"github.com/segmentio/kafka-go"
	"time"
)

var logCh = make(chan *dnsLog, 10000)

type logWriter interface {
	Write(log *dnsLog) error
}

func logHandler(kafkaAddresses []string, kafkaTopic string) {
	var writers []logWriter
	//if viper.GetString("output_file_prefix") != "" {
	//	writers = append(writers, newFileWriter(viper.GetString("output_file_prefix")))
	//}
	if len(kafkaAddresses) > 0 {
		writers = append(writers, newKafkaWriter(kafkaAddresses, kafkaTopic))
	}
	var err error
	for log := range logCh {
		for _, w := range writers {
			err = w.Write(log)
			if err != nil {
				fmt.Printf("error in writing log: %v\n", err)
			}
		}
		logPool.Put(log)
	}
}

type kafkaWriter struct {
	kw                 *kafka.Writer
	lastFlushTimestamp int64
	cache              []kafka.Message
}

func newKafkaWriter(addr []string, topic string) *kafkaWriter {
	return &kafkaWriter{kw: &kafka.Writer{
		Addr:     kafka.TCP(addr...),
		Topic:    topic,
		Balancer: &kafka.LeastBytes{},
		Async:    true,
	}}
}

func (w *kafkaWriter) Write(log *dnsLog) error {
	w.cache = append(w.cache, kafka.Message{
		Key:   []byte("dns_log"),
		Value: []byte(fmt.Sprintf("%s|%s|%s|%d|%s|%d|%d|%d|%s|%d|%d", log.RemoteIP, "127.0.0.1", log.Qname, log.Banned, log.RelatedRuleSet, log.UseCache, log.Qclass, log.Qtype, log.Response, log.ReceiveTimestamp, log.ResponseTimestamp)),
	})
	if len(w.cache) >= 100 || time.Now().Unix()-w.lastFlushTimestamp >= 3 {
		defer func() {
			w.cache = []kafka.Message{}
			w.lastFlushTimestamp = time.Now().Unix()
		}()
		return w.kw.WriteMessages(context.TODO(), w.cache...)
	}
	return nil
}

//type fileWriter struct {
//	fw *file.FileWriter
//}
//
//func newFileWriter(prefix string) *fileWriter {
//	w := &fileWriter{}
//	w.fw = file.NewFileWriter(prefix)
//	w.fw.ZeroSegmentation = true
//	if Debug {
//		w.fw.FileMode = file.REALTIME
//	}
//	w.fw.GenerateFilename = func(name string, index int) string {
//		if Debug {
//			return fmt.Sprintf("%s-debug-%d-%s.log", name, viper.GetInt("runningId"), time.Now().Format("20060102"))
//		} else {
//			return fmt.Sprintf("%s-%s.log", name, time.Now().Format("20060102"))
//		}
//	}
//	return w
//}
//func (w *fileWriter) Write(log *dnsLog) error {
//	logString := fmt.Sprintf("%s|%s|%s|%d|%s|%d|%d|%d|%s|%d|%d\n", log.RemoteIP, selfIP, log.Qname, log.Banned, log.RelatedRuleSet, log.UseCache, log.Qclass, log.Qtype, log.Response, log.ReceiveTimestamp, log.ResponseTimestamp)
//	return w.fw.WriteString(logString)
//}
