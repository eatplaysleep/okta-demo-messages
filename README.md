# Express Resource Server Example

This sample application uses the [Okta JWT Verifier][] library to authenticate requests against your Express application, using access tokens.

The access tokens are obtained via the [Auth Code Flow][].  As such, you will need to use one of our front-end samples with this project.  It is the responsibility of the front-end to authenticate the user, then use the obtained access tokens to make requests of this resource server.


## Prerequisites

Before running this sample, you will need the following:

* An Okta Developer Account, you can sign up for one at https://developer.okta.com/signup/.
* An Okta Application, configured for Single-Page App (SPA) mode. This is done from the Okta Developer Console and you can find instructions [here][OIDC SPA Setup Instructions].  When following the wizard, use the default properties.  They are are designed to work with our sample applications.
* One of our front-end sample applications to demonstrate the interaction with the resource server:
  * [Okta React Typescript Sample App][] <- Recommended
  * [Okta Angular Sample Apps][]
  * [Okta React Sample Apps][]
  * [Okta Vue Sample Apps][]

## Running This Example

### Gather Variables

You will need to gather the following information from the Okta Developer Console:

| Variable | |
| --- | --- |
| `SPA_CLIENT_ID` | The client ID of the SPA application that you created earlier. This can be found on the "General" tab of an application, or the list of applications.  This identifies the application that tokens will be minted for. |
| `AUD` | This is the value configured on your authorization server. If you are using the `default` authorization server, this value should be `api://default`. |
| `ISSUER` | This is the URL of the authorization server that will perform authentication.  All Developer Accounts have a "default" authorization server.  The issuer is a combination of your Org URL (found in the upper right of the console home page) and `/oauth2/default`. For example, `https://dev-1234.oktapreview.com/oauth2/default`. |

These values must exist as environment variables. They can be exported in the shell, or saved in a file named `.env`, at the root of this repository. See [dotenv](https://www.npmjs.com/package/dotenv) for more details on this file format.

If opting to deploy via Vercel, you will be prompted to enter these values after clicking the button.

```ini
ISSUER=https://yourOktaDomain.com/oauth2/default
SPA_CLIENT_ID=123xxxxx123
AUD=api://default
```

### Option 1 (Recommended)
For the easiest option, [sign up](https://vercel.com/signup) for a free Vercel account and click the following button.

When prompted, enter the appropriate environmental variables.

* _For the `CI` variable, enter `false`._
* _See [here](https://vercel.com/docs/get-started) for more details on how to use Vercel._

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Featplaysleep%2Fokta-demo-messages&env=SPA_CLIENT_ID,AUD,ISSUER,CI)

___
### Option 2

To run this application, you first need to clone this repo and then enter into this directory:

```bash
git clone https://github.com/eatplaysleep/okta-demo-messages.git \
&& cd okta-demo-messages
```

Then install dependencies:

```bash
npm install
```

With variables set, start the resource server:

```
npm start
```

Now navigate to http://localhost:8000 in your browser.

If you see a basic welcome message, then things are working!  Now open a new terminal window and run the front-end sample project of your choice (see links in Prerequisites).  Once the front-end sample is running, you can navigate to http://localhost:8080 in your browser and log in to the front-end application.  Once logged in you can navigate to the "Messages" page to see the interaction with the resource server.

[Auth Code Flow]: https://developer.okta.com/docs/guides/implement-grant-type/authcodepkce/main
[Okta React Typescript Sample App]: https://github.com/eatplaysleep/okta-react-typescript/tree/s
[Okta Angular Sample Apps]: https://github.com/okta/samples-js-angular
[Okta React Sample Apps]: https://github.com/okta/samples-js-react
[Okta Vue Sample Apps]: https://github.com/okta/samples-js-vue
[Okta JWT Verifier]: https://github.com/okta/okta-oidc-js/tree/master/packages/jwt-verifier
[OIDC SPA Setup Instructions]: https://developer.okta.com/authentication-guide/implementing-authentication/implicit#1-setting-up-your-application
