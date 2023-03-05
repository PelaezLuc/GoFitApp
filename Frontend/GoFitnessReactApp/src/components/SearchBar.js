import { useState } from "react"

export const SearchBar = ({workouts}) => {

    const [value, setValue] = useState

    const onChange = (e) => {
        setValue(e.target.value);
    }

    const onSearch = (searchTerm) => {
        setValue(searchTerm);
    };

    return(
        <>
        <span>🔎 </span>
        <input type="search" className="search-input" placeholder="Buscar" />
        </>
    )
}