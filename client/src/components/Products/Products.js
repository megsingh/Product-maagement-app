import React, { useEffect, useState } from 'react';
import axios from "axios";
import { Link, useHistory } from 'react-router-dom'
import { getToken } from '../utils/authOperations'

import "./products.css"

import plusicon from "../../images/plus.webp"

const ProductList = () => {
  const history = useHistory()
  const [products, setProducts] = useState([])
  let config = {
    headers: {
      Authorization: 'Bearer ' + getToken()
    }
  }
  console.log(config);
  useEffect(() => {
    axios.get(`http://localhost:5000/api/products`,config).then(res => {
      console.log("Axios", res.data);
      setProducts(res.data)
    })
  }, [])

  const handleLogout = () => {
    if (window.confirm("Are you sure you want to logout?") === true) {
      localStorage.removeItem("user")
      history.push("/")
    }
  }


  const handleDelete = (id) => {
    axios.delete(`http://localhost:5000/api/products/delete/${id}`, config).then(res => {
      console.log("res", res);
      window.location.href = "/products";
    })
  }

  const handleEdit = (id) => {
    axios.put(`http://localhost:5000/api/products/edit/${id}`,{},config).then(res => {
      console.log("res", res);
      window.location.href = "/products";
    })
  }

  const deliveredStyle = {
    color: "green",
    fontWeight: "bold"
  }

  const notDeliveredStyle = {
    color: "red",
    fontWeight: "bold"
  }


  return (
    <div className='product'>
      <div>
        <a href='/' className='logout__button' onClick={handleLogout}>Logout</a>
      </div>
      <header>
        <h1>Products</h1>
        <div>
          <Link className='new__product' to="/products/add">
            <img className='add__icon' src={plusicon} alt="add product" /></Link>
        </div>
      </header>
      <ul className='product__list'>

        {products.map((item, index) => {
          return (
            <li key={index}>
              <div className='product__container'>
                <div className='product__header'>
                  <label><strong className='title'>{item.title}</strong></label>
                  <p className='Author'>{item.author}</p>
                  { item.delivered ?
                  (<p style = {deliveredStyle}>Delivered</p>):
                  (<p style = {notDeliveredStyle}>Not delivered</p>)}
                  </div>
                    <div>
                     {!item.delivered && <button onClick={() => handleEdit(item._id)} className='product__button'>Update delivery status</button>} 
                    
                    <button onClick={() => handleDelete(item._id)} className='product__button'>Delete</button>
                  
                  </div>
                </div>
            </li>)
        })}
      </ul>

    </div>

  );
}

export default ProductList;
