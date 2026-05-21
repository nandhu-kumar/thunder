/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	authnprovidercm "github.com/thunder-id/thunderid/internal/authnprovider/common"
	"github.com/thunder-id/thunderid/internal/system/config"
	"github.com/thunder-id/thunderid/internal/system/error/serviceerror"
	systemhttp "github.com/thunder-id/thunderid/internal/system/http"
	"github.com/thunder-id/thunderid/internal/system/i18n/core"
	"github.com/thunder-id/thunderid/internal/system/log"
)

const (
	sunbirdRCAuthnProviderComponentName = "SunbirdRCAuthnProvider"
	sunbirdRCIndividualIDKey            = "individualId"
)

var errSunbirdRCKBIAuthFailed = errors.New("sunbirdrc_kbi_auth_failed")

type sunbirdRCFieldDetail struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Type        string `json:"type"`
}

type sunbirdRCSearchFilter struct {
	Eq string `json:"eq"`
}

type sunbirdRCSearchRequest struct {
	Filters map[string]sunbirdRCSearchFilter `json:"filters"`
}

type sunbirdRCAuthnProvider struct {
	cfg        config.SunbirdRCAuthnProviderConfig
	httpClient systemhttp.HTTPClientInterface
	logger     *log.Logger
}

var _ AuthnProviderInterface = (*sunbirdRCAuthnProvider)(nil)

func newSunbirdRCAuthnProvider(
	cfg config.SunbirdRCAuthnProviderConfig,
	httpClient systemhttp.HTTPClientInterface,
) *sunbirdRCAuthnProvider {
	return &sunbirdRCAuthnProvider{
		cfg:        cfg,
		httpClient: httpClient,
		logger:     log.GetLogger().With(log.String(log.LoggerKeyComponentName, sunbirdRCAuthnProviderComponentName)),
	}
}

func (p *sunbirdRCAuthnProvider) Authenticate(
	ctx context.Context,
	identifiers, credentials map[string]interface{},
	_ *authnprovidercm.AuthnMetadata,
) (*authnprovidercm.AuthnResult, *serviceerror.ServiceError) {
	individualID, ok := identifiers[sunbirdRCIndividualIDKey].(string)
	if !ok || individualID == "" {
		p.logger.Error("individualId missing or invalid in identifiers")
		return nil, p.authFailedError()
	}

	fields, _ := parseSunbirdRCFieldDetails(p.cfg.FieldDetails)
	kbiFields := make(map[string]string, len(fields))
	for _, f := range fields {
		if f.ID == p.cfg.IDField {
			continue
		}
		val, ok := credentials[f.ID].(string)
		if !ok || val == "" {
			p.logger.Error("KBI field missing or invalid in credentials", log.String("field", f.ID))
			return nil, p.authFailedError()
		}
		kbiFields[f.ID] = val
	}

	entityID, err := p.validateKBI(ctx, individualID, kbiFields)
	if err != nil {
		if errors.Is(err, errSunbirdRCKBIAuthFailed) {
			return nil, p.authFailedError()
		}
		p.logger.Error("SunbirdRC registry search failed", log.Error(err))
		internalErr := serviceerror.InternalServerError
		return nil, &internalErr
	}

	return &authnprovidercm.AuthnResult{
		Token:          entityID,
		ExternalSub:    entityID,
		UserID:         entityID,
		IsExistingUser: true,
	}, nil
}

func (p *sunbirdRCAuthnProvider) GetAttributes(
	ctx context.Context,
	token string,
	_ *authnprovidercm.RequestedAttributes,
	_ *authnprovidercm.GetAttributesMetadata,
) (*authnprovidercm.GetAttributesResult, *serviceerror.ServiceError) {
	if p.cfg.EntityURL == "" {
		return &authnprovidercm.GetAttributesResult{EntityID: token}, nil
	}

	entityData, err := p.fetchEntityData(ctx, p.cfg.EntityURL, token)
	if err != nil {
		p.logger.Error("Failed to fetch SunbirdRC entity data",
			log.MaskedString("entityId", token), log.Error(err))
		internalErr := serviceerror.InternalServerError
		return nil, &internalErr
	}

	mappedClaims := buildSunbirdRCMappedClaims(entityData, p.cfg.ClaimsMapping, p.logger)
	attrs := make(map[string]*authnprovidercm.AttributeResponse, len(mappedClaims))
	for k, v := range mappedClaims {
		attrs[k] = &authnprovidercm.AttributeResponse{Value: v}
	}

	return &authnprovidercm.GetAttributesResult{
		EntityID: token,
		AttributesResponse: &authnprovidercm.AttributesResponse{
			Attributes: attrs,
		},
	}, nil
}

func (p *sunbirdRCAuthnProvider) validateKBI(
	ctx context.Context,
	individualID string,
	kbiFields map[string]string,
) (string, error) {
	filters := make(map[string]sunbirdRCSearchFilter, len(kbiFields)+1)
	filters[p.cfg.IDField] = sunbirdRCSearchFilter{Eq: individualID}
	for fieldID, fieldValue := range kbiFields {
		filters[fieldID] = sunbirdRCSearchFilter{Eq: fieldValue}
	}

	reqBody, err := json.Marshal(sunbirdRCSearchRequest{Filters: filters})
	if err != nil {
		return "", fmt.Errorf("failed to marshal registry search request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.SearchURL, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("failed to build registry search request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("registry search request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("registry search returned status %d", resp.StatusCode)
	}

	var results []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return "", fmt.Errorf("failed to decode registry search response: %w", err)
	}

	if len(results) != 1 {
		return "", errSunbirdRCKBIAuthFailed
	}

	entityIDVal, ok := results[0][p.cfg.EntityIDField]
	if !ok {
		return "", fmt.Errorf("entity_id_field %q not found in registry response", p.cfg.EntityIDField)
	}
	entityID, ok := entityIDVal.(string)
	if !ok || entityID == "" {
		return "", fmt.Errorf("entity_id_field %q has invalid value in registry response", p.cfg.EntityIDField)
	}

	return entityID, nil
}

func (p *sunbirdRCAuthnProvider) fetchEntityData(
	ctx context.Context,
	entityBaseURL string,
	entityID string,
) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/%s", entityBaseURL, entityID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build entity fetch request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("entity fetch request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("entity fetch returned status %d", resp.StatusCode)
	}

	var entityData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&entityData); err != nil {
		return nil, fmt.Errorf("failed to decode entity fetch response: %w", err)
	}

	return entityData, nil
}

func (p *sunbirdRCAuthnProvider) authFailedError() *serviceerror.ServiceError {
	return &serviceerror.ServiceError{
		Type: serviceerror.ClientErrorType,
		Code: authnprovidercm.ErrorCodeAuthenticationFailed,
		Error: core.I18nMessage{
			Key:          "error.authnproviderservice.authentication_failed",
			DefaultValue: "Authentication failed",
		},
		ErrorDescription: core.I18nMessage{
			Key:          "error.authnproviderservice.authentication_failed_description",
			DefaultValue: "The provided credentials could not be verified",
		},
	}
}

func parseSunbirdRCFieldDetails(jsonStr string) ([]sunbirdRCFieldDetail, error) {
	if jsonStr == "" {
		return nil, errors.New("field_details is empty")
	}
	var fields []sunbirdRCFieldDetail
	if err := json.Unmarshal([]byte(jsonStr), &fields); err != nil {
		return nil, fmt.Errorf("invalid field_details JSON: %w", err)
	}
	return fields, nil
}

func parseSunbirdRCClaimsMapping(jsonStr string) (map[string]string, error) {
	var mapping map[string]string
	if err := json.Unmarshal([]byte(jsonStr), &mapping); err != nil {
		return nil, fmt.Errorf("invalid claims_mapping JSON: %w", err)
	}
	return mapping, nil
}

func buildSunbirdRCMappedClaims(
	entityData map[string]interface{},
	claimsMappingJSON string,
	logger *log.Logger,
) map[string]interface{} {
	if claimsMappingJSON == "" {
		out := make(map[string]interface{}, len(entityData))
		for k, v := range entityData {
			out[k] = v
		}
		return out
	}

	claimsMapping, err := parseSunbirdRCClaimsMapping(claimsMappingJSON)
	if err != nil {
		logger.Warn("Failed to parse claims_mapping; using raw entity data", log.Error(err))
		out := make(map[string]interface{}, len(entityData))
		for k, v := range entityData {
			out[k] = v
		}
		return out
	}

	mapped := make(map[string]interface{}, len(claimsMapping))
	for oidcClaim, registryField := range claimsMapping {
		if val, ok := entityData[registryField]; ok {
			mapped[oidcClaim] = val
		}
	}
	return mapped
}
