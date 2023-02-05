package tokenauth

import (
	"context"
	"fmt"
	"github.com/orchestd/cacheStorage"
	"github.com/orchestd/configurations/config"
	"github.com/orchestd/configurations/config/confgetter"
	"github.com/orchestd/configurations/credentials"
	"testing"
	"time"
)

const TimeLayoutYYYYMMDD_HHMMSS = "2006-01-02 15:04:05"

type MockConfig struct{}

func (conf MockConfig) Get(key string) config.Value {
	values := make(map[string]interface{})
	values["jwt_secret"] = "jwt_secret"
	values["encrypt_key"] = "testEncryptKey"
	confGetterWrapper := confgetter.NewConfgetterWrapper(values)
	return confGetterWrapper.Get(key)
}

func (config MockConfig) GetCredentials() credentials.Credentials {
	return credentials.Credentials{}
}

func (config MockConfig) Implementation() interface{} {
	return nil
}

type MockCacheStorageGetter struct{}

func (g MockCacheStorageGetter) GetById(c context.Context, collectionName string, id string, ver string, dest interface{}) cacheStorage.CacheStorageError {
	return nil
}

func (g MockCacheStorageGetter) GetManyByIds(c context.Context, collectionName string, ids []string, ver string, dest interface{}) cacheStorage.CacheStorageError {
	return nil
}

func (g MockCacheStorageGetter) GetAll(c context.Context, collectionName string, ver string, dest interface{}) cacheStorage.CacheStorageError {
	return nil
}

func (g MockCacheStorageGetter) GetLatestVersions(c context.Context) ([]cacheStorage.CacheVersion, cacheStorage.CacheStorageError) {
	return nil, nil
}

func (g MockCacheStorageGetter) GetLatestCollectionVersion(c context.Context, collection string) (cacheStorage.CacheVersion, cacheStorage.CacheStorageError) {
	return cacheStorage.CacheVersion{}, nil
}

type MockCacheStorageSetter struct{}

func (s MockCacheStorageSetter) Insert(c context.Context, collectionName string, id string, ver string, item interface{}) cacheStorage.CacheStorageError {
	insertCalls++
	return nil
}

func (s MockCacheStorageSetter) InsertMany(c context.Context, collectionName string, ver string, items map[string]interface{}) cacheStorage.CacheStorageError {
	return nil
}

func (s MockCacheStorageSetter) InsertOrUpdate(c context.Context, collectionName string, id string, ver string, item interface{}) cacheStorage.CacheStorageError {
	return nil
}

func (s MockCacheStorageSetter) Update(c context.Context, collectionName string, id string, ver string, item interface{}) cacheStorage.CacheStorageError {
	return nil
}

func (s MockCacheStorageSetter) Remove(c context.Context, collectionName string, id string, ver string) cacheStorage.CacheStorageError {
	return nil
}

func (s MockCacheStorageSetter) RemoveAll(c context.Context, collectionName string, ver string) cacheStorage.CacheStorageError {
	return nil
}

var insertCalls = 0

func TestCreateReadToken(t *testing.T) {
	protectedData := make(map[string]interface{})
	protectedData["data1"] = "protectedData1"
	protectedData["data2"] = "protectedData2"
	plainData := make(map[string]interface{})
	plainData["data1"] = "plainData1"
	plainData["data2"] = "plainData2"
	sessionId := "testSessionID"
	customerId := "testCustomerID"

	createdAccessToken := ""
	createdRefreshToken := ""
	now, _ := time.Parse(TimeLayoutYYYYMMDD_HHMMSS, "2021-07-07 10:10:00")

	Convey("Creating access and refresh token", t, func() {
		conf := MockConfig{}
		mockCacheStorageGetter := MockCacheStorageGetter{}
		mockCacheStorageSetter := MockCacheStorageSetter{}
		jwtToken := NewJwtToken(conf, mockCacheStorageGetter, mockCacheStorageSetter)
		accessToken, refreshToken, err := jwtToken.CreateTokensPair(context.TODO(), now, sessionId, customerId, protectedData, plainData)
		So(err, ShouldBeNil)
		So(accessToken, ShouldNotBeEmpty)
		So(refreshToken, ShouldNotBeEmpty)
		So(insertCalls, ShouldEqual, 1)
		createdAccessToken = accessToken
		createdRefreshToken = refreshToken
	})

	fmt.Println(createdRefreshToken)

	Convey("Check validity of not expired access token", t, func() {
		conf := MockConfig{}
		mockCacheStorageGetter := MockCacheStorageGetter{}
		mockCacheStorageSetter := MockCacheStorageSetter{}
		jwtToken := NewJwtToken(conf, mockCacheStorageGetter, mockCacheStorageSetter)
		plainData, protectedData, err := jwtToken.ValidateAndGetData(context.TODO(), now.Add((accessTokenLifeTimeMin/2)*time.Minute), createdAccessToken)
		So(err, ShouldBeNil)
		So(plainData, ShouldNotBeNil)
		So(protectedData, ShouldNotBeNil)

		So(protectedData["data1"], ShouldEqual, "protectedData1")
		So(protectedData["data2"], ShouldEqual, "protectedData2")

		So(plainData["data1"], ShouldEqual, "plainData1")
		So(plainData["data2"], ShouldEqual, "plainData2")

	})

	Convey("Check validity of expired access token", t, func() {
		conf := MockConfig{}
		mockCacheStorageGetter := MockCacheStorageGetter{}
		mockCacheStorageSetter := MockCacheStorageSetter{}
		jwtToken := NewJwtToken(conf, mockCacheStorageGetter, mockCacheStorageSetter)
		_, _, err := jwtToken.ValidateAndGetData(context.TODO(), now.Add((accessTokenLifeTimeMin+1)*time.Minute), createdAccessToken)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, "Token is expired")
	})

	Convey("Check validity of not expired refresh token", t, func() {
		conf := MockConfig{}
		mockCacheStorageGetter := MockCacheStorageGetter{}
		mockCacheStorageSetter := MockCacheStorageSetter{}
		jwtToken := NewJwtToken(conf, mockCacheStorageGetter, mockCacheStorageSetter)
		plainData, protectedData, err := jwtToken.ValidateAndGetData(context.TODO(), now.Add((refreshTokenLifeTimeMin/2)*time.Minute), createdRefreshToken)

		So(err, ShouldBeNil)

		So(protectedData["data1"], ShouldEqual, "protectedData1")
		So(protectedData["data2"], ShouldEqual, "protectedData2")

		So(protectedData["sessionId"], ShouldEqual, sessionId)
		So(protectedData["customerId"], ShouldEqual, customerId)
		So(protectedData["uuid"], ShouldNotBeEmpty)

		So(plainData["data1"], ShouldEqual, "plainData1")
		So(plainData["data2"], ShouldEqual, "plainData2")
	})

	Convey("Check validity of expired refresh token", t, func() {
		conf := MockConfig{}
		mockCacheStorageGetter := MockCacheStorageGetter{}
		mockCacheStorageSetter := MockCacheStorageSetter{}
		jwtToken := NewJwtToken(conf, mockCacheStorageGetter, mockCacheStorageSetter)
		_, _, err := jwtToken.ValidateAndUseRefreshToken(context.TODO(), now.Add((refreshTokenLifeTimeMin+1)*time.Minute), createdRefreshToken)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, "Token is expired")
	})
}
