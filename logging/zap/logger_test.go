// Copyright 2022 CloudWeGo Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package zap

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudwego/kitex/pkg/klog"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func stdoutProvider(ctx context.Context) func() {
	provider := sdktrace.NewTracerProvider()
	otel.SetTracerProvider(provider)

	exp, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	if err != nil {
		panic(err)
	}

	bsp := sdktrace.NewBatchSpanProcessor(exp)
	provider.RegisterSpanProcessor(bsp)

	return func() {
		if err := provider.Shutdown(ctx); err != nil {
			panic(err)
		}
	}
}

// testEncoderConfig encoder config for testing, copy from zap
func testEncoderConfig() zapcore.EncoderConfig {
	return zapcore.EncoderConfig{
		MessageKey:     "msg",
		LevelKey:       "level",
		NameKey:        "name",
		TimeKey:        "ts",
		CallerKey:      "caller",
		FunctionKey:    "func",
		StacktraceKey:  "stacktrace",
		LineEnding:     "\n",
		EncodeTime:     zapcore.EpochTimeEncoder,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
}

// humanEncoderConfig copy from zap
func humanEncoderConfig() zapcore.EncoderConfig {
	cfg := testEncoderConfig()
	cfg.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncodeLevel = zapcore.CapitalLevelEncoder
	cfg.EncodeDuration = zapcore.StringDurationEncoder
	return cfg
}

// TestLogger test logger work with opentelemetry
func TestLogger(t *testing.T) {
	ctx := context.Background()

	buf := new(bytes.Buffer)

	shutdown := stdoutProvider(ctx)
	defer shutdown()

	logger := NewLogger(
		WithTraceErrorSpanLevel(zap.WarnLevel),
		WithRecordStackTraceInSpan(true),
	)
	defer func() {
		err := logger.Sync()
		if err != nil {
			return
		}
	}()

	klog.SetLogger(logger)
	klog.SetOutput(buf)
	klog.SetLevel(klog.LevelDebug)

	logger.Info("log from origin zap")
	assert.True(t, strings.Contains(buf.String(), "log from origin zap"))
	buf.Reset()

	tracer := otel.Tracer("test otel std logger")

	ctx, span := tracer.Start(ctx, "root")

	klog.CtxInfof(ctx, "hello %s", "world")
	assert.True(t, strings.Contains(buf.String(), "trace_id"))
	assert.True(t, strings.Contains(buf.String(), "span_id"))
	assert.True(t, strings.Contains(buf.String(), "trace_flags"))
	buf.Reset()

	span.End()

	ctx, child1 := tracer.Start(ctx, "child1")

	klog.CtxTracef(ctx, "trace %s", "this is a trace log")
	klog.CtxDebugf(ctx, "debug %s", "this is a debug log")
	klog.CtxInfof(ctx, "info %s", "this is a info log")

	child1.End()
	assert.Equal(t, codes.Unset, child1.(sdktrace.ReadOnlySpan).Status().Code)

	ctx, child2 := tracer.Start(ctx, "child2")
	klog.CtxNoticef(ctx, "notice %s", "this is a notice log")
	klog.CtxWarnf(ctx, "warn %s", "this is a warn log")
	klog.CtxErrorf(ctx, "error %s", "this is a error log")

	child2.End()
	assert.Equal(t, codes.Error, child2.(sdktrace.ReadOnlySpan).Status().Code)

	_, errSpan := tracer.Start(ctx, "error")

	klog.Info("no trace context")

	errSpan.End()
}

// TestLogLevel test SetLevel
func TestLogLevel(t *testing.T) {
	buf := new(bytes.Buffer)

	logger := NewLogger(
		WithTraceErrorSpanLevel(zap.WarnLevel),
		WithRecordStackTraceInSpan(true),
	)
	defer func() {
		err := logger.Sync()
		if err != nil {
			return
		}
	}()

	// output to buffer
	logger.SetOutput(buf)

	logger.Debug("this is a debug log")
	assert.False(t, strings.Contains(buf.String(), "this is a debug log"))

	logger.SetLevel(klog.LevelDebug)

	logger.Debugf("this is a debug log %s", "msg")
	assert.True(t, strings.Contains(buf.String(), "this is a debug log"))
}

// TestCoreOption test zapcore config option
func TestCoreOption(t *testing.T) {
	buf := new(bytes.Buffer)

	logger := NewLogger(
		WithCoreEnc(zapcore.NewConsoleEncoder(humanEncoderConfig())),
		WithCoreLevel(zap.NewAtomicLevelAt(zapcore.WarnLevel)),
		WithCoreWs(zapcore.AddSync(buf)),
	)
	defer func() {
		err := logger.Sync()
		if err != nil {
			return
		}
	}()

	logger.SetOutput(buf)

	logger.Debug("this is a debug log")
	// test log level
	assert.False(t, strings.Contains(buf.String(), "this is a debug log"))

	logger.Error("this is a warn log")
	// test log level
	assert.True(t, strings.Contains(buf.String(), "this is a warn log"))
	// test console encoder result
	assert.True(t, strings.Contains(buf.String(), "\tERROR\t"))
}

// TestCoreOption test zapcore config option
func TestZapOption(t *testing.T) {
	buf := new(bytes.Buffer)

	logger := NewLogger(
		WithZapOptions(zap.AddCaller()),
	)
	defer func() {
		err := logger.Sync()
		if err != nil {
			return
		}
	}()

	logger.SetOutput(buf)

	logger.Debug("this is a debug log")
	assert.False(t, strings.Contains(buf.String(), "this is a debug log"))

	logger.Error("this is a warn log")
	// test caller in log result
	assert.True(t, strings.Contains(buf.String(), "caller"))
}

// TestCtxLogger test kv logger work with ctx
func TestCtxKVLogger(t *testing.T) {
	ctx := context.Background()

	buf := new(bytes.Buffer)

	shutdown := stdoutProvider(ctx)
	defer shutdown()

	logger := NewLogger(
		WithTraceErrorSpanLevel(zap.WarnLevel),
		WithRecordStackTraceInSpan(true),
	)
	defer func() {
		err := logger.Sync()
		if err != nil {
			return
		}
	}()

	tracer := otel.Tracer("test otel std logger")

	klog.SetLogger(logger)
	klog.SetOutput(buf)
	klog.SetLevel(klog.LevelTrace)

	for k, level := range []klog.Level{
		klog.LevelTrace,
		klog.LevelDebug,
		klog.LevelInfo,
	} {
		ctx, span := tracer.Start(ctx, fmt.Sprintf("child1-%d", k))
		logger.CtxLogf(level, ctx, "log from origin zap %s=%s", "k1", "v1")

		assert.True(t, strings.Contains(buf.String(), "log from origin zap"))
		assert.True(t, strings.Contains(buf.String(), "k1"))
		assert.True(t, strings.Contains(buf.String(), "v1"))
		assert.Equal(t, codes.Unset, span.(sdktrace.ReadOnlySpan).Status().Code)

		span.End()
		buf.Reset()
	}

	for k, level := range []klog.Level{
		klog.LevelNotice,
		klog.LevelWarn,
		klog.LevelError,
		// klog.LevelFatal,
	} {
		ctx, span := tracer.Start(ctx, fmt.Sprintf("child2-%d", k))
		logger.CtxLogf(level, ctx, "log from origin zap %s=%s", "k1", "v1")

		assert.True(t, strings.Contains(buf.String(), "log from origin zap"))
		assert.True(t, strings.Contains(buf.String(), "k1"))
		assert.True(t, strings.Contains(buf.String(), "v1"))
		assert.Equal(t, codes.Error, span.(sdktrace.ReadOnlySpan).Status().Code)

		span.End()
		buf.Reset()
	}

	for k, level := range []klog.Level{
		klog.LevelTrace,
		klog.LevelDebug,
		klog.LevelInfo,
	} {
		ctx, span := tracer.Start(ctx, fmt.Sprintf("child3-%d", k))
		logger.CtxKVLog(ctx, level, "log from origin zap", "k1", "v1")

		assert.True(t, strings.Contains(buf.String(), "log from origin zap"))
		assert.True(t, strings.Contains(buf.String(), "k1"))
		assert.True(t, strings.Contains(buf.String(), "v1"))
		assert.Equal(t, codes.Unset, span.(sdktrace.ReadOnlySpan).Status().Code)

		span.End()
		buf.Reset()
	}

	for k, level := range []klog.Level{
		klog.LevelNotice,
		klog.LevelWarn,
		klog.LevelError,
		// klog.LevelFatal,
	} {
		ctx, span := tracer.Start(ctx, fmt.Sprintf("child4-%d", k))
		logger.CtxKVLog(ctx, level, "log from origin zap", "k1", "v1")

		assert.True(t, strings.Contains(buf.String(), "log from origin zap"))
		assert.True(t, strings.Contains(buf.String(), "k1"))
		assert.True(t, strings.Contains(buf.String(), "v1"))
		assert.Equal(t, codes.Error, span.(sdktrace.ReadOnlySpan).Status().Code)

		span.End()
		buf.Reset()
	}
}
