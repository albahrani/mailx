package main

import (
	"context"

	pb "github.com/albahrani/mailx/client/proto"
	"google.golang.org/grpc"
)

type mockClientService struct {
	register      func(context.Context, *pb.RegisterRequest, ...grpc.CallOption) (*pb.RegisterResponse, error)
	login         func(context.Context, *pb.LoginRequest, ...grpc.CallOption) (*pb.LoginResponse, error)
	sendMessage   func(context.Context, *pb.SendMessageRequest, ...grpc.CallOption) (*pb.SendMessageResponse, error)
	listMessages  func(context.Context, *pb.ListMessagesRequest, ...grpc.CallOption) (*pb.ListMessagesResponse, error)
	getMessage    func(context.Context, *pb.GetMessageRequest, ...grpc.CallOption) (*pb.GetMessageResponse, error)
	getContactKey func(context.Context, *pb.GetContactKeyRequest, ...grpc.CallOption) (*pb.GetContactKeyResponse, error)
	acceptContact func(context.Context, *pb.AcceptContactRequest, ...grpc.CallOption) (*pb.AcceptContactResponse, error)
}

func (m *mockClientService) Register(ctx context.Context, in *pb.RegisterRequest, opts ...grpc.CallOption) (*pb.RegisterResponse, error) {
	if m.register == nil {
		return nil, nil
	}
	return m.register(ctx, in, opts...)
}

func (m *mockClientService) Login(ctx context.Context, in *pb.LoginRequest, opts ...grpc.CallOption) (*pb.LoginResponse, error) {
	if m.login == nil {
		return nil, nil
	}
	return m.login(ctx, in, opts...)
}

func (m *mockClientService) SendMessage(ctx context.Context, in *pb.SendMessageRequest, opts ...grpc.CallOption) (*pb.SendMessageResponse, error) {
	if m.sendMessage == nil {
		return nil, nil
	}
	return m.sendMessage(ctx, in, opts...)
}

func (m *mockClientService) ListMessages(ctx context.Context, in *pb.ListMessagesRequest, opts ...grpc.CallOption) (*pb.ListMessagesResponse, error) {
	if m.listMessages == nil {
		return nil, nil
	}
	return m.listMessages(ctx, in, opts...)
}

func (m *mockClientService) GetMessage(ctx context.Context, in *pb.GetMessageRequest, opts ...grpc.CallOption) (*pb.GetMessageResponse, error) {
	if m.getMessage == nil {
		return nil, nil
	}
	return m.getMessage(ctx, in, opts...)
}

func (m *mockClientService) GetContactKey(ctx context.Context, in *pb.GetContactKeyRequest, opts ...grpc.CallOption) (*pb.GetContactKeyResponse, error) {
	if m.getContactKey == nil {
		return nil, nil
	}
	return m.getContactKey(ctx, in, opts...)
}

func (m *mockClientService) AcceptContact(ctx context.Context, in *pb.AcceptContactRequest, opts ...grpc.CallOption) (*pb.AcceptContactResponse, error) {
	if m.acceptContact == nil {
		return nil, nil
	}
	return m.acceptContact(ctx, in, opts...)
}
