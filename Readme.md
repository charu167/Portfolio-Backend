**BOILER PLATE CODE FOR NODEJS BACKEND (MONGO DB INTEGRATED)**

**Description:**

While setting up any nodeJS project there are certain things that a deveoper needs to do everytime like setting up the right folder structure, building the authentication system, connecting the database, etc. what if there was a boiler plate code for all this and more?
This project aims to make developers' lives easier by providing a codebase which has a NodeJS stander folder structure, a fully fledged authentication system using middlewares, a sample API endpoint for testing the authentication system, database connectivity, etc.
And there's more...
Often, creating a new mongo db cluster and connecting it to the nodeJS application is a hastle because it takes time. This poject comes with Docker i.s containerization. Once you build the project and run it, docker will take care of the creating and connecting the database.
Feel free to use it for all kinds of different NdeJS applications!

**Installation:**

Clone this repo: `git clone https://github.com/charu167/node-template.git`

Remove the remote repository: `git remote remove origin`

Add your own remote repository: `git remote add origin https;//github.com/<your-github>/<your-repository>`

Run project for the first time: `docker-compose up --build`

For all other times: `docker-compose up`
