import { Route,Redirect } from 'react-router-dom';
import { isAuthenticated } from "../components/utils/authOperations"
import React from 'react';

  function PrivateRoute({ children,...rest}) {
    return (
     
      <Route
      {...rest}
        render={
          () => (
            isAuthenticated()
              ? (
                children
              ) : (
                <Redirect
                  to="/"
                />
              ))
        }
      />
    );
  }
  
  export default PrivateRoute;
  
  