import { Link } from "react-router-dom"

export const HeaderNav = () => {
    return ( 
        <ul className="nav-list">
            <Link to={'/login'} className="nav-list-link">
                <li className="nav-list-item">Login</li>
                <span className="item-line"></span>
            </Link>
            <Link to={'/register'} className="nav-list-link">
                <li className="nav-list-item">Registro</li>
                <span className="item-line"></span>
            </Link>
        </ul>
    )
}

//función para que cuando haya que mostrar el login o register se muestre correctamente


// {!isAuth && 
//     <ul class="nav-list">
//        <li class="nav-list-item">Login</li>
//        <li class="nav-list-item">Register</li>
//     </ul>}


// {!isAuth && 
//     <ul class="nav-list">
//        <li class="nav-list-item">Login</li>
//        <li class="nav-list-item">Register</li>
//     </ul>}



