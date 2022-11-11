# Custom-Scope-Validator

The custom scope validator extends the default JDBC scope validator to override its default behaviour of terminating the authentication flow if any unauthorized scopes were requested. This extended scope validator allows the authentication flow to complete for any scope request while dropping the scopes which are not authorized for the user based on roles assigned.

*Steps to deploy*
- Build the project using maven `mvn clean install`
- Copy the binary file from `target` directory into `<IS_HOME>/repository/components/dropins` directory
- Add folowing config to the deployment.toml file.
```
[[oauth.custom_scope_validator]]
class = "org.wso2.custom.scope.validator.CustomScopeValidator"
```
- Restart WSO2 IS
- Select `Custom scope validator` as the Scope Validator in `Inbound Authentication Configuration` of Service provider configuration as example below.

 ![Screenshot 2022-11-11 at 4 28 50 PM](https://user-images.githubusercontent.com/42811248/201326756-27d5ecb5-f0a4-4349-92f8-18b3e12e9db0.png)
