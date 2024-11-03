# Trents Hackathon Backend

This is the backend for the Trent Hackathon project.

## Running

The project uses `yarn` to manage dependencies the commands are outlined below:

- `yarn dev` to build and run the server
- `yarn build` will build the server and output to `dist`
- `yarn start` will run the server from `dist`

In order to run the projects you will need to copy the `.env.example` into a `.env` file and fill out the values make sure that they are kept secret. After than run the below commands:

```bash
yarn # Install dependencies
yarn build # Build the server
yarn start # Run the server
```

## Installing Yarn

If you do not have yarn installed you can install it by running the following command:

```bash
corepack enable
yarn set version stable
```
