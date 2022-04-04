import './App.css';
import React from 'react';
import { BrowserRouter as Router, Switch, Route } from "react-router-dom"
import Login from './components/Login/Login';
import Register from './components/Resgister/Register';
import ProductAdd from './components/Form/ProductAdd';
import ProductList from './components/Products/Products';
import PrivateRoute from './routes/PrivateRoute'

function App() {
   
    return (
        <Router>

            <Switch>
                <Route exact path="/">
                    <Login />
                </Route>
                <Route exact path="/register">
                    <Register />
                </Route>
                <PrivateRoute exact path="/products">
                    <ProductList />
                </PrivateRoute>
                <PrivateRoute exact path="/products/add/">
                    <ProductAdd />
                </PrivateRoute>
            </Switch>

        </Router>

    )
}

export default App;