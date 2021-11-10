/**
 * /*
 * Copyright (c) 2018, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 *
 * @format
 */

const express = require('express');
const OktaJwtVerifier = require('@okta/jwt-verifier');
var cors = require('cors');

const CLIENT_ID = process.env.SPA_CLIENT_ID,
	ISSUER = process.env.ISSUER,
	AUD = process.env.AUD ?? 'api://default';
PORT = process.env.PORT ?? 8080;

const oktaJwtVerifier = new OktaJwtVerifier({
	clientId: CLIENT_ID,
	issuer: ISSUER,
	assertClaims: {
		aud: AUD,
		cid: CLIENT_ID,
	},
});

/**
 * A simple middleware that asserts valid access tokens and sends 401 responses
 * if the token is not present or fails validation.  If the token is valid its
 * contents are attached to req.jwt
 */
const authenticationRequired = async (req, res, next) => {
	try {
		const authHeader = req.headers.authorization || '';
		const match = authHeader.match(/Bearer (.+)/);

		if (!match) {
			res.status(401);
			return next('Unauthorized');
		}

		const accessToken = match[1];
		const audience = AUD;

		const result = await oktaJwtVerifier.verifyAccessToken(
			accessToken,
			audience
		);
		const jwt = result?.jwt;

		next();
	} catch (error) {
		console.error(error);
		res.status(401).send(error.message);
	}
};

const app = express();

/**
 * For local testing only!  Enables CORS for all domains
 */
app.use(cors());

app.get('/', (req, res) => {
	res.json({
		message:
			"Hello!  There's not much to see here :) Please grab one of our front-end samples for use with this sample resource server",
	});
});

/**
 * An example route that requires a valid access token for authentication, it
 * will echo the contents of the access token if the middleware successfully
 * validated the token.
 */
app.get('/secure', authenticationRequired, (req, res) => {
	res.json(req.jwt);
});

/**
 * Another example route that requires a valid access token for authentication, and
 * print some messages for the user if they are authenticated
 */
app.get('/api/messages', authenticationRequired, (req, res) => {
	res.json({
		messages: [
			{
				date: new Date(),
				text: 'I am a robot.',
			},
			{
				date: new Date(new Date().getTime() - 1000 * 60 * 60),
				text: 'Hello, world!',
			},
		],
	});
});

app.listen(PORT, () => {
	console.log(`Resource Server Ready on port ${PORT}`);
});
