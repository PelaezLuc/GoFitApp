import { createContext, useEffect, useState } from "react";


export const UserAuthContext = createContext();

export const UserAuthProviderComponent = ({children}) => {
    const [userAuth, setUserAuth] = useState(JSON.parse(localStorage.getItem('userAuth')));

    useEffect(() => {
        localStorage.setItem('userAuth', JSON.stringify(userAuth));
    }, [userAuth]);

    return (
        <UserAuthContext.Provider value={{ userAuth, setUserAuth }}>
            {children}
        </UserAuthContext.Provider>
    );
};
