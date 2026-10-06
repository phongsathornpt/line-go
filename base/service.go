package base

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/phongsathornpt/line-go/thrift"
	"github.com/phongsathornpt/line-go/types"
)

// ServiceName identifies one of the Thrift service endpoints exported by
// LINEJS.
type ServiceName string

// ServiceDefinition describes one service's endpoint, wire protocol, and RPC
// methods present in the pinned LINEJS schema.
type ServiceDefinition struct {
	Name            ServiceName
	Endpoint        string
	Protocol        thrift.Protocol
	Methods         []string
	MethodEndpoints map[string]string
}

// ErrUnknownService indicates a service name absent from the pinned catalog.
var ErrUnknownService = errors.New("line: unknown Thrift service")

// ErrUnknownServiceMethod indicates a method not listed for a service.
var ErrUnknownServiceMethod = errors.New("line: unknown Thrift service method")

// ServiceDefinitions returns a detached copy of the LINEJS Thrift service
// catalog.
func ServiceDefinitions() []ServiceDefinition {
	definitions := make([]ServiceDefinition, len(linejsServiceCatalog))
	for index, definition := range linejsServiceCatalog {
		definitions[index] = definition
		definitions[index].Methods = append([]string(nil), definition.Methods...)
		definitions[index].MethodEndpoints = cloneServiceEndpoints(definition.MethodEndpoints)
	}
	return definitions
}

// RPCService performs typed Thrift calls for one LINEJS service endpoint.
type RPCService struct {
	client     *BaseClient
	definition ServiceDefinition
}

// Service resolves a Thrift service from the pinned LINEJS catalog.
func (c *BaseClient) Service(name ServiceName) (*RPCService, error) {
	if c != nil {
		if service, found := c.services[name]; found {
			return service, nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownService, name)
}

// Definition returns this service's endpoint and a detached method list.
func (s *RPCService) Definition() ServiceDefinition {
	definition := s.definition
	definition.Methods = append([]string(nil), definition.Methods...)
	definition.MethodEndpoints = cloneServiceEndpoints(definition.MethodEndpoints)
	return definition
}

// ServiceCallOptions controls a typed RPC call's timeout and extra headers.
type ServiceCallOptions struct {
	Timeout time.Duration
	Long    bool
	Headers http.Header
}

// CallTyped sends a Thrift request using generated Args and Result DTOs. args
// must be a generated args struct; result, when non-nil, must point to its
// generated result envelope.
func (s *RPCService) CallTyped(ctx context.Context, method string, args, result any) (Response, error) {
	return s.CallTypedWithOptions(ctx, ServiceCallOptions{}, method, args, result)
}

// CallTypedWithOptions is CallTyped with request timeout and header overrides.
func (s *RPCService) CallTypedWithOptions(ctx context.Context, options ServiceCallOptions, method string, args, result any) (Response, error) {
	if s == nil || s.client == nil {
		return Response{}, fmt.Errorf("line service: client is nil")
	}
	if !containsMethod(s.definition.Methods, method) {
		return Response{}, fmt.Errorf("%w: %s.%s", ErrUnknownServiceMethod, s.definition.Name, method)
	}
	response, err := s.requestTyped(ctx, options, method, args, result)
	if err != nil {
		return response, err
	}
	if serviceErr := serviceException(method, result); serviceErr != nil {
		var remote *ServiceError
		if s.definition.Name != ServiceNameAccessTokenRefresh &&
			errors.As(serviceErr, &remote) && remote.Code == int32(types.ErrorCodeMUSTREFRESHV3TOKEN) {
			available, checkErr := s.client.hasRefreshToken(ctx)
			if checkErr != nil {
				return response, fmt.Errorf("line %s.%s: check refresh token: %w", s.definition.Name, method, checkErr)
			}
			if available {
				if _, refreshErr := s.client.Auth().TryRefreshToken(ctx); refreshErr != nil {
					return response, refreshErr
				}
				resetResult(result)
				response, err = s.requestTyped(ctx, options, method, args, result)
				if err != nil {
					return response, err
				}
				if retryErr := serviceException(method, result); retryErr != nil {
					return response, retryErr
				}
				return response, nil
			}
		}
		return response, serviceErr
	}
	return response, nil
}

func (s *RPCService) requestTyped(ctx context.Context, options ServiceCallOptions, method string, args, result any) (Response, error) {
	path := s.definition.Endpoint
	if override := s.definition.MethodEndpoints[method]; override != "" {
		path = override
	}
	return s.client.RequestTyped(ctx, RequestOptions{
		Path:     path,
		Method:   method,
		Protocol: s.definition.Protocol,
		Timeout:  options.Timeout,
		Long:     options.Long,
		Headers:  options.Headers,
	}, args, result)
}

func (c *BaseClient) hasRefreshToken(ctx context.Context) (bool, error) {
	value, found, err := c.storage.Get(ctx, "refreshToken")
	if err != nil {
		return false, err
	}
	token, ok := value.(string)
	return found && ok && token != "", nil
}

func resetResult(result any) {
	value := reflect.ValueOf(result)
	if value.IsValid() && value.Kind() == reflect.Pointer && !value.IsNil() && value.Elem().CanSet() {
		value.Elem().SetZero()
	}
}

func containsMethod(methods []string, wanted string) bool {
	for _, method := range methods {
		if method == wanted {
			return true
		}
	}
	return false
}

func serviceException(method string, result any) error {
	value := reflect.ValueOf(result)
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return nil
	}
	for index := 0; index < value.NumField(); index++ {
		fieldDefinition := value.Type().Field(index)
		field := value.Field(index)
		if !isNonzeroThriftField(fieldDefinition, field) || isReflectNil(field) {
			continue
		}
		return serviceErrorFromException(method, field)
	}
	return nil
}

func isNonzeroThriftField(definition reflect.StructField, value reflect.Value) bool {
	parts := strings.Split(definition.Tag.Get("thrift"), ",")
	if len(parts) < 2 {
		return false
	}
	fieldID, err := strconv.Atoi(parts[0])
	if err != nil || fieldID == 0 {
		return false
	}
	if definition.Name == "E" {
		return true
	}
	typeOfField := definition.Type
	for typeOfField.Kind() == reflect.Pointer {
		typeOfField = typeOfField.Elem()
	}
	if typeOfField.Kind() == reflect.Struct && strings.Contains(strings.ToLower(typeOfField.Name()), "exception") {
		return true
	}
	if definition.Name == "Error" {
		if typeOfField.Kind() == reflect.String {
			return reflectString(value) != ""
		}
		if typeOfField.Kind() >= reflect.Int && typeOfField.Kind() <= reflect.Int64 {
			return reflectInt32(value) != 0
		}
	}
	return false
}

func cloneServiceEndpoints(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	clone := make(map[string]string, len(source))
	for method, endpoint := range source {
		clone[method] = endpoint
	}
	return clone
}

func serviceErrorFromException(method string, exception reflect.Value) error {
	for exception.IsValid() && (exception.Kind() == reflect.Pointer || exception.Kind() == reflect.Interface) {
		if exception.IsNil() {
			return nil
		}
		exception = exception.Elem()
	}
	if !exception.IsValid() || exception.Kind() != reflect.Struct {
		remoteType := "unknown"
		if exception.IsValid() {
			if exception.Kind() == reflect.String {
				return &ServiceError{Method: method, Reason: exception.String()}
			}
			if exception.Kind() >= reflect.Int && exception.Kind() <= reflect.Int64 {
				return &ServiceError{Method: method, Code: int32(exception.Int())}
			}
			remoteType = exception.Type().String()
		}
		return &ServiceError{Method: method, Reason: fmt.Sprintf("remote exception %s", remoteType)}
	}
	code := reflectInt32(exception.FieldByName("Code"))
	if code == 0 {
		code = reflectInt32(exception.FieldByName("ErrorCode"))
	}
	reason := reflectString(exception.FieldByName("Reason"))
	if reason == "" {
		reason = reflectString(exception.FieldByName("ErrorMessage"))
	}
	if reason == "" {
		reason = reflectString(exception.FieldByName("Message"))
	}
	parameters := reflectStringMap(exception.FieldByName("ParameterMap"))
	return &ServiceError{Method: method, Code: code, Reason: reason, Parameters: parameters}
}

func isReflectNil(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func reflectInt32(value reflect.Value) int32 {
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return 0
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return 0
	}
	switch value.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return int32(value.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int32(value.Uint())
	case reflect.String:
		parsed, _ := strconv.ParseInt(value.String(), 10, 32)
		return int32(parsed)
	default:
		return 0
	}
}

func reflectString(value reflect.Value) string {
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return ""
		}
		value = value.Elem()
	}
	if value.IsValid() && value.Kind() == reflect.String {
		return value.String()
	}
	return ""
}

func reflectStringMap(value reflect.Value) map[string]string {
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Map || value.Type().Key().Kind() != reflect.String || value.Type().Elem().Kind() != reflect.String {
		return nil
	}
	result := make(map[string]string, value.Len())
	iterator := value.MapRange()
	for iterator.Next() {
		result[iterator.Key().String()] = iterator.Value().String()
	}
	return result
}
