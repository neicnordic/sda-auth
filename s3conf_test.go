package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// These are not complete tests of all functions in elixir. New tests should
// be added as the code is updated.

type S3ConfTests struct {
	suite.Suite
}

func TestS3ConfTestSuite(t *testing.T) {
	suite.Run(t, new(S3ConfTests))
}

func (suite *S3ConfTests) SetupTest() {}

func (suite *S3ConfTests) TearDownTest() {}

func (suite *S3ConfTests) TestGetS3ConfigMap() {

	// variable values
	token := "tokenvaluestring"
	inboxHost := "s3://inboxHost"
	user := "s3user"

	// static values

	check_ssl_certificate := "False"
	check_ssl_hostname := "False"
	encoding := "UTF-8"
	encrypt := "False"
	guess_mime_type := "True"
	human_readable_sizes := "True"
	chunk_size := 50
	use_https := "True"
	socket_timeout := 30

	s3conf := getS3ConfigMap(token, inboxHost, user)

	assert.Equal(suite.T(), user, s3conf["access_key"], fmt.Sprintf("access_key should be %v", user))
	assert.Equal(suite.T(), user, s3conf["secret_key"], fmt.Sprintf("secret_key should be %v", user))
	assert.Equal(suite.T(), token, s3conf["access_token"], fmt.Sprintf("access_token should be %v", token))
	assert.Equal(suite.T(), check_ssl_certificate, s3conf["check_ssl_certificate"], fmt.Sprintf("check_ssl_certificate should be %v", check_ssl_certificate))
	assert.Equal(suite.T(), check_ssl_hostname, s3conf["check_ssl_hostname"], fmt.Sprintf("check_ssl_hostname should be %v", check_ssl_hostname))
	assert.Equal(suite.T(), encoding, s3conf["encoding"], fmt.Sprintf("encoding should be %v", encoding))
	assert.Equal(suite.T(), encrypt, s3conf["encrypt"], fmt.Sprintf("encrypt should be %v", encrypt))
	assert.Equal(suite.T(), guess_mime_type, s3conf["guess_mime_type"], fmt.Sprintf("guess_mime_type should be %v", guess_mime_type))
	assert.Equal(suite.T(), inboxHost, s3conf["host_base"], fmt.Sprintf("host_base should be %v", inboxHost))
	assert.Equal(suite.T(), inboxHost, s3conf["host_bucket"], fmt.Sprintf("host_bucket should be %v", inboxHost))
	assert.Equal(suite.T(), human_readable_sizes, s3conf["human_readable_sizes"], fmt.Sprintf("human_readable_sizes should be %v", human_readable_sizes))
	assert.Equal(suite.T(), fmt.Sprintf("%v", chunk_size), s3conf["multipart_chunk_size_mb"], fmt.Sprintf("multipart_chunk_size_mb should be %v", chunk_size))
	assert.Equal(suite.T(), use_https, s3conf["use_https"], fmt.Sprintf("use_https should be '%v'", use_https))
	assert.Equal(suite.T(), fmt.Sprintf("%v", socket_timeout), s3conf["socket_timeout"], fmt.Sprintf("socket_timeout should be %v", socket_timeout))

}
