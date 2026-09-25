// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package profiles // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor/internal/profiles"

import (
	"context"
	"slices"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/contexts/xprofile/ottlprofile"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor/internal/common"
)

type parsedContextStatements struct {
	common.ProfilesConsumer
	sharedCache bool
}

type Processor struct {
<<<<<<< HEAD
	contexts            []parsedContextStatements
	logger              *zap.Logger
	sharedCacheContexts []common.ContextID
=======
	contexts     []parsedContextStatements
	logger       *zap.Logger
	sharedCaches map[common.ContextID]*pcommon.Map
>>>>>>> pre-release
}

func NewProcessor(contextStatements []common.ContextStatements, errorMode ottl.ErrorMode, settings component.TelemetrySettings, profileFunctions map[string]ottl.Factory[*ottlprofile.TransformContext]) (*Processor, error) {
	pc, err := common.NewProfileParserCollection(settings, common.WithProfileParser(profileFunctions), common.WithProfileErrorMode(errorMode))
	if err != nil {
		return nil, err
	}

	contexts := make([]parsedContextStatements, len(contextStatements))
	var errors error
	for i, cs := range contextStatements {
		context, err := pc.ParseContextStatements(cs)
		if err != nil {
			errors = multierr.Append(errors, err)
		}
		contexts[i] = parsedContextStatements{
			ProfilesConsumer: context,
			sharedCache:      cs.SharedCache,
		}
	}

	if errors != nil {
		return nil, errors
	}

<<<<<<< HEAD
	var sharedCacheContexts []common.ContextID
	for _, c := range contexts {
		if !c.sharedCache || slices.Contains(sharedCacheContexts, c.Context()) {
			continue
		}
		sharedCacheContexts = append(sharedCacheContexts, c.Context())
	}

	return &Processor{
		contexts:            contexts,
		logger:              settings.Logger,
		sharedCacheContexts: sharedCacheContexts,
=======
	var sharedCaches map[common.ContextID]*pcommon.Map
	for _, c := range contexts {
		if c.sharedCache {
			if sharedCaches == nil {
				sharedCaches = map[common.ContextID]*pcommon.Map{}
			}
			m := pcommon.NewMap()
			sharedCaches[c.Context()] = &m
		}
	}

	return &Processor{
		contexts:     contexts,
		logger:       settings.Logger,
		sharedCaches: sharedCaches,
>>>>>>> pre-release
	}, nil
}

func (p *Processor) ProcessProfiles(ctx context.Context, ld pprofile.Profiles) (pprofile.Profiles, error) {
	sharedCaches := common.NewSharedCaches(p.sharedCacheContexts)

	for _, c := range p.contexts {
<<<<<<< HEAD
		cache := common.LoadContextCache(sharedCaches, c.Context(), c.sharedCache)
=======
		cache := common.LoadContextCache(p.sharedCaches, c.Context(), c.sharedCache)
>>>>>>> pre-release
		err := c.ConsumeProfiles(ctx, ld, cache)
		if err != nil {
			p.logger.Error("failed processing profiles", zap.Error(err))
			return ld, err
		}
	}

	return ld, nil
}
