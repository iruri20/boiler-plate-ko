import React from "react";
import {
  BrowserRouter as Router,
  Switch,
  Route,
  Link
} from "react-router-dom";
import LandingPage from './components/views/LandingPage/LandingPage'
import LoginPage from "./components/views/LoginPage/LoginPage";
import RegisterPage from "./components/views/RegisterPage/RegisterPage";

function App() {
  return (
    <Router>
      <div>
        {/* A <Switch> looks through its children <Route>s and
            renders the first one that matches the current URL. */}
        <Switch>
          <Route exact path="/" component={LandingPage}>
          </Route>
          <Route exact path="/login" component={LoginPage}>
          </Route>
          <Route exact path="/register" component={RegisterPage}>
          </Route>
        </Switch>
      </div>
    </Router>
  );
}

export default App
